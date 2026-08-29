// Which images the bundled Containerfiles start from: the remote ones, so the image-producing
// verbs can refresh them before a build, and the launcher-built ones, which order every cleanup
// list. Reading is deliberately narrow: these Containerfiles are this repository's own, so a shape
// this does not resolve is a deliberate edit, and refusing it beats approximating it — an
// approximation would skip a refresh in silence.

package agentsandbox.launcher

import scala.util.matching.Regex

import HostCommands.fail

object ContainerfileSources:

  /**
   * The shapes those Containerfiles use, and only those: one `ARG NAME[=value]` a line,
   * `FROM <ref> [AS <name>]`, `COPY --from=<ref>`, `RUN --mount=...,from=<ref>`, and `${NAME}`.
   * Extend it when a bundled Containerfile needs one it refuses — the remote-source test reads
   * every one of them, so the file and line reach CI rather than a build.
   */
  private val ContainerfileArg = """(?i:ARG)\s+([^\s"'\\]+)""".r
  private val ContainerfileFrom = """(?i:FROM)\s+(\S+)(?:\s+(?i:AS)\s+(\S+))?""".r
  private val ContainerfileVariable = """\$\{([A-Za-z_][A-Za-z0-9_]*)\}""".r

  /** A `--mount`'s own `from=`, which names an image to Podman exactly as `COPY --from=` does. */
  private val ContainerfileMountFrom = """(?:^|,)from=([^,]+)""".r

  /**
   * A parser directive reads as a comment but is not one: `# escape=` alone rewrites what a line
   * continuation looks like, which would hide a `--from=` on the line after it.
   */
  private val ContainerfileDirective = """#\s*[A-Za-z][A-Za-z0-9_-]*\s*=.*""".r

  /**
   * Whether a reference names its registry, by the rule containers/image applies to the component
   * before the first slash (distribution/reference's splitDockerDomain): `localhost`, or a `.` or
   * `:` in it, or any uppercase — a namespace cannot hold uppercase, so it must be a host. Without
   * one Podman resolves the name through the host's registries.conf, which this cannot do for it.
   */
  private def isQualifiedImage(reference: String): Boolean =
    val slash = reference.indexOf('/')
    if slash <= 0 then false
    else
      val first = reference.take(slash)
      first == "localhost" || first.exists(character => character == '.' || character == ':') ||
        first != first.toLowerCase(java.util.Locale.ROOT)

  /**
   * What one Containerfile builds on, with its ARG values resolved: the registry-held images it
   * names anywhere, and the launcher-built images its stages start `FROM` — its parents, without
   * `localhost/`, so they compare with the tags the launcher builds. A `COPY --from` or mount of a
   * launcher-built image is not a parent: the copied bytes outlive the source, and Podman removes
   * it freely.
   */
  case class ImageSources(remote: Vector[String], parents: Vector[String])

  def remoteImagesInContainerfile(
    name: String,
    text: String,
    buildArgs: Map[String, String],
    localImages: Set[String],
    target: Option[String],
  ): Either[String, Vector[String]] =
    imageSourcesInContainerfile(name, text, buildArgs, localImages, target).map(_.remote)

  def imageSourcesInContainerfile(
    name: String,
    text: String,
    buildArgs: Map[String, String],
    localImages: Set[String],
    target: Option[String],
  ): Either[String, ImageSources] =
    // A FROM reads only the arguments declared before the first one; every other instruction reads
    // its own stage, which inherits a global only where the stage redeclares it (Dockerfile ARG
    // scope). One map for both would let a later stage's value pick a different image than Podman.
    // Podman stores a locally built image under `localhost/`, so both spellings name it: one
    // normalization for the declared set and the reference, or a name matches under neither.
    val declared = localImages.map(_.stripPrefix("localhost/"))
    var global = Map.empty[String, String]
    var stage = Map.empty[String, String]
    var stages = Map.empty[String, Map[String, String]]
    var stageName: Option[String] = None
    var stageIndex = -1
    val images = Vector.newBuilder[String]
    val parents = Vector.newBuilder[String]
    var refusal: Option[String] = None
    var complete = false
    var carried = ""
    var continued = false
    var inOptions = true

    def namesStage(stop: String): Boolean =
      stop == stageIndex.toString || stageName.contains(stop)

    text.linesIterator.zipWithIndex.foreach: (physical, index) =>
      val line = physical.trim
      def refuse(reason: String): Unit =
        if refusal.isEmpty then refusal = Some(s"error: $reason in $name:${index + 1}: $line")

      def collect(reference: String, values: Map[String, String], parent: Boolean = false): Unit =
        val expanded = ContainerfileVariable.replaceAllIn(reference, matched =>
          values.get(matched.group(1)) match
            case Some(value) => Regex.quoteReplacement(value)
            case None =>
              refuse(s"no value for build-image variable ${matched.matched}")
              "",
        )
        if refusal.isEmpty then
          // A name is one of four things, and the order decides which: the empty base or an
          // earlier stage, an image this launcher builds, an image a registry holds, or a short
          // name only the host's registries.conf could place. Testing the registry syntax before
          // the launcher's own images would schedule a pull for one it is about to build.
          if expanded.contains('$') then refuse("unsupported build-image variable")
          else if expanded == "scratch" || stages.contains(expanded) then ()
          else if declared.contains(expanded.stripPrefix("localhost/")) then
            if parent then parents += expanded.stripPrefix("localhost/")
          else if isQualifiedImage(expanded) then images += expanded
          else refuse(s"unqualified image source $expanded")

      if refusal.isEmpty && !complete && line.nonEmpty && line.startsWith("#") then
        if ContainerfileDirective.matches(line) then refuse("unsupported parser directive")
      else if refusal.isEmpty && !complete && line.nonEmpty then
        val content = if line.endsWith("\\") then line.dropRight(1).trim else line
        val words = content.split("\\s+").toVector
        // A continuation carries its instruction and its place in it, so an option on a later
        // physical line is read, and `from=` in a command's own words is not mistaken for one.
        val keyword =
          if continued then carried else words.head.toUpperCase(java.util.Locale.ROOT)
        val operands = if continued then words else words.drop(1)
        if !continued then inOptions = true
        carried = keyword

        // A here-document's body is shell input, not instructions: reading it would take a COPY
        // written for the shell as an image to pull, and a FROM in it would reset the stage.
        if content.contains("<<") then refuse("unsupported here-document")
        // A continued ARG hides half its value, and a continued FROM reads the escape as its
        // reference; a continued COPY or RUN is read option by option below.
        else if (keyword == "ARG" || keyword == "FROM") && line.endsWith("\\") then
          refuse("continued instruction")
        else if keyword == "ARG" then
          line match
            case ContainerfileArg(declaration) =>
              val separator = declaration.indexOf('=')
              val argument = if separator < 0 then declaration else declaration.take(separator)
              buildArgs
                .get(argument)
                .orElse(Option.when(separator >= 0)(declaration.drop(separator + 1)))
                .orElse(if stageIndex >= 0 then global.get(argument) else None)
                .foreach: value =>
                  if stageIndex >= 0 then stage = stage.updated(argument, value)
                  else global = global.updated(argument, value)
            case _ => refuse("unsupported ARG instruction")
        else if keyword == "FROM" then
          line match
            case ContainerfileFrom(reference, name) =>
              // A stage built on an earlier one starts from that stage's arguments, and every
              // stage answers to its position as well as its name — `COPY --from=0` reaches an
              // unnamed one (imagebuilder's NewStages keys argInstructionsInStages by both).
              // Closing the previous stage first is what lets this FROM name it.
              if stageIndex >= 0 then
                stages = stages.updated(stageIndex.toString, stage)
                stageName.foreach(previous => stages = stages.updated(previous, stage))
              // `--target` stops the build there, and Buildah builds only that stage and what it
              // depends on. Modelling a later one needs the stage graph, so only a first-stage
              // target is read — every one this launcher passes names the first stage, and
              // anything else stops the verb rather than reading what Podman never evaluates.
              if target.isDefined && stageIndex >= 0 then
                if stageIndex == 0 && namesStage(target.get) then complete = true
                else refuse(s"unsupported build target ${target.get}: only the first stage is read")
              if !complete && refusal.isEmpty then
                collect(reference, global, parent = true)
                stageIndex += 1
                // Buildah compares a stage name exactly (executor.go's stageIndexUnlocked), so
                // `AS Build` is not reachable as `build`: matching case-insensitively would
                // inherit a scope Podman does not, and resolve the descendant differently.
                stage = stages.getOrElse(reference, Map.empty)
                if Option(name).exists(_.contains('$')) then refuse("unsupported stage alias")
                stageName = Option(name)
            case _ => refuse("unsupported FROM instruction")
        else
          operands.foreach: word =>
            if !word.startsWith("--") then inOptions = false
            else if inOptions then
              if keyword == "COPY" && word.startsWith("--from=") then
                collect(word.stripPrefix("--from="), stage)
              else if keyword == "RUN" && word.startsWith("--mount=") then
                ContainerfileMountFrom
                  .findAllMatchIn(word.stripPrefix("--mount="))
                  .foreach(matched => collect(matched.group(1), stage))

        continued = line.endsWith("\\")

    // A one-stage Containerfile closes its only stage here rather than at a later FROM.
    if refusal.isEmpty && !complete then
      target.filterNot(stop => stageIndex == 0 && namesStage(stop)).foreach: stop =>
        refusal = Some(s"error: unsupported build target $stop in $name: only the first stage is read")
    refusal.toLeft(ImageSources(images.result().distinct, parents.result().distinct))

  /**
   * Every flag the launcher's own build commands pass, and whether it takes a following value.
   * Anything else — `--build-arg=NAME=value`, `--file`, a `--build-context` naming an image, or a
   * `--build-arg NAME` whose value Podman takes from the environment — would resolve a different
   * source from the one Podman builds, so it is refused rather than read. The generated-command
   * test pins the set from the other side.
   */
  val BuildCommandFlags =
    Map("--build-arg" -> true, "--label" -> true, "--target" -> true, "-t" -> true, "-f" -> true,
      "--no-cache" -> false)

  /**
   * The Containerfile and build arguments one launcher build command hands Podman, read back from
   * the command itself so no Containerfile a verb builds can be left out of the refresh.
   */
  private case class BuildSpecification(
    containerfile: String,
    buildArgs: Map[String, String],
    target: Option[String],
  )

  private def imageBuildSpecification(command: Vector[String]): BuildSpecification =
    def refuse(reason: String): Nothing = fail(s"error: $reason: ${command.mkString(" ")}")
    if command.lift(1) != Some("build") then refuse("expected an image build command")
    val buildArgs = Map.newBuilder[String, String]
    var containerfile: Option[String] = None
    var target: Option[String] = None
    var index = 2
    while index < command.size - 1 do
      val flag = command(index)
      BuildCommandFlags.get(flag) match
        case None        => refuse(s"unsupported build command flag $flag")
        case Some(false) => index += 1
        case Some(true) =>
          if index + 1 >= command.size - 1 then refuse(s"$flag without a value")
          val value = command(index + 1)
          if flag == "-f" then containerfile = Some(value)
          else if flag == "--target" then target = Some(value)
          else if flag == "--build-arg" then
            val separator = value.indexOf('=')
            if separator <= 0 then
              refuse(s"--build-arg $value takes its value from the environment")
            buildArgs += value.take(separator) -> value.drop(separator + 1)
          index += 2
    BuildSpecification(
      containerfile.getOrElse(s"${command.last}/Containerfile"),
      buildArgs.result(),
      target,
    )

  /** Sources derived from the same contexts and arguments Podman receives, one per command. */
  def imageSourcesForBuildCommands(
    commands: Vector[Vector[String]],
    readContainerfile: String => String,
    localImages: Set[String],
  ): Vector[ImageSources] =
    commands.map: command =>
      val specification = imageBuildSpecification(command)
      val name = specification.containerfile
      imageSourcesInContainerfile(
        name,
        readContainerfile(name),
        specification.buildArgs,
        localImages,
        specification.target,
      ).fold(message => fail(message), identity)

  def remoteImagesForBuildCommands(
    commands: Vector[Vector[String]],
    readContainerfile: String => String,
    localImages: Set[String],
  ): Vector[String] =
    imageSourcesForBuildCommands(commands, readContainerfile, localImages).flatMap(_.remote).distinct

  /**
   * Pull separately: downstream Containerfiles mix remote sources with launcher-owned local bases,
   * so putting --pull=always on their builds would also look for those local names in registries.
   * Bare `pull` has always semantics; spelling that as --policy=always requires Podman 5.6 for no
   * behavior change. Do not use `newer`: it suppresses pull errors when a local image exists.
   *
   * --quiet, because the default output answers the wrong question: it is the copier's per-layer
   * report, printed for every layer before the store is asked whether it already holds it, so an
   * unchanged image and a fresh download look alike. What is wanted is whether the image changed,
   * and podman does not say; --quiet leaves the image id, and runBuilds adds the verdict.
   */
  def remoteImagePullCommands(podman: String, images: Vector[String]): Vector[Vector[String]] =
    images.map(image => Vector(podman, "pull", image, "--quiet"))
