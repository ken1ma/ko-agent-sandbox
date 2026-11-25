package koreview

import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import java.nio.file.{Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*

/** `defaults codex`: the model and reasoning effort that Codex's local configuration selects for this repository, for
  * the skill to offer first. ko-review/doc/design.md, "Defaults", describes the output.
  */
object CodexDefaults:

  def apply(ctx: CommandContext, root: Path): JsonObject =
    var model: Option[(String, String)] = None
    var effort: Option[(String, String)] = None
    for layer <- configLayers(ctx, root) if Files.isRegularFile(layer) do
      val config = parseToml(layer)
      if model.isEmpty then model = config.get("model").collect { case value: String => value -> layer.toString }
      if effort.isEmpty then
        effort = config.get("model_reasoning_effort").collect { case value: String => value -> layer.toString }
    val catalog = this.catalog(ctx)
    val listed = catalog.map(_.filterNot(_.hidden))
    val recommendedModel = model.map(_._1).orElse(listed.flatMap(_.headOption).map(_.model))
    val entry = catalog.getOrElse(Nil).find(model => recommendedModel.contains(model.model))
    JsonObject(
      "model" -> model.map(_._1).asJson,
      "effort" -> effort.map(_._1).asJson,
      "source" -> Json.obj("model" -> model.map(_._2).asJson, "effort" -> effort.map(_._2).asJson),
      "partial" -> true.asJson,
      "catalog" -> listed.map(_.map(_.toJson)).asJson,
      "recommended" -> Json.obj(
        "model" -> recommendedModel.asJson,
        "effort" -> effort.map(_._1).orElse(entry.flatMap(_.defaultEffort)).asJson,
        "efforts" -> entry.map(_.efforts).asJson,
        "upgrade" -> entry.flatMap(_.upgrade).map: upgrade =>
          Json.obj("model" -> upgrade("model").getOrElse(Json.Null),
            "migrationMarkdown" -> upgrade("migration_markdown").getOrElse(Json.Null))
        .asJson,
      ),
    )

  private final case class Model(model: String, description: Option[String], defaultEffort: Option[String],
      efforts: Vector[String], hidden: Boolean, upgrade: Option[JsonObject]):
    def toJson: Json = Json.obj("model" -> model.asJson, "description" -> description.asJson,
      "defaultEffort" -> defaultEffort.asJson, "efforts" -> efforts.asJson)

  /** Codex's model catalog sorted by `priority`, as Codex sorts the list its `/model` picker shows and takes its
    * default model from, or None when Codex cannot render it. `hidden` marks the models the picker leaves out. */
  private def catalog(ctx: CommandContext): Option[Vector[Model]] =
    for
      program <- ctx.find("codex")
      (status, out, _) <- Reviewer.output(ctx, Seq(program.toString, "debug", "models"))
      if status == 0
      models <- io.circe.parser.parse(out).toOption.flatMap(_.hcursor.downField("models").focus).flatMap(_.asArray)
    yield models.flatMap(_.asObject).filter(_("slug").exists(_.isString))
      .sortBy(model => model("priority").flatMap(_.asNumber).flatMap(_.toInt).fold(Double.PositiveInfinity)(_.toDouble))
      .map: model =>
        def text(key: String) = model(key).flatMap(_.asString)
        Model(
          text("slug").get,
          text("description"),
          text("default_reasoning_level"),
          model("supported_reasoning_levels").flatMap(_.asArray).getOrElse(Vector.empty)
            .flatMap(_.asObject.flatMap(_("effort")).flatMap(_.asString)),
          !text("visibility").contains("list"),
          model("upgrade").flatMap(_.asObject),
        )

  /** The configuration files that Codex reads for this repository, highest precedence first: the project's
    * `.codex/config.toml` when the user configuration trusts the project or its main worktree, the user
    * configuration, and the image's system layer. Codex's cloud-managed layer is not on disk. */
  private def configLayers(ctx: CommandContext, root: Path): Seq[Path] =
    val home = ctx.env.get("CODEX_HOME").map(Path.of(_))
      .getOrElse(Path.of(ctx.env.getOrElse("HOME", System.getProperty("user.home")), ".codex"))
    val user = home.resolve("config.toml")
    val layers = Seq(user, Path.of("/etc/codex/config.toml"))
    val project = root.resolve(".codex/config.toml")
    if !(Files.isRegularFile(project) && Files.isRegularFile(user)) then layers
    else
      val projects = parseToml(user).get("projects") match
        case Some(table: Map[?, ?]) => table.asInstanceOf[Map[String, Any]]
        case _ => Map.empty[String, Any]
      val main = mainWorktree(root)
      // Codex looks the main worktree up by its canonical path, then by the path as found.
      val keys = Seq(root.toString) ++ main.toSeq.flatMap(path => Seq(path.toRealPath().toString, path.toString))
      val trust = keys.iterator.flatMap(key => projects.get(key)).collectFirst:
        case table: Map[?, ?] if table.asInstanceOf[Map[String, Any]].contains("trust_level") =>
          table.asInstanceOf[Map[String, Any]]("trust_level")
      if trust.contains("trusted") then project +: layers else layers

  /** The values of a TOML file, tables as maps. */
  private def parseToml(path: Path): Map[String, Any] =
    val parsed =
      try org.tomlj.Toml.parse(path)
      catch case ex: java.io.IOException => throw Codex.error("REVIEWER_CONFIG_UNREADABLE", s"$path: $ex")
    if parsed.hasErrors then
      throw Codex.error("REVIEWER_CONFIG_UNREADABLE", s"$path: ${parsed.errors().asScala.mkString("; ")}")
    def convert(table: org.tomlj.TomlTable): Map[String, Any] =
      table.keySet().asScala.toSeq.map: key =>
        key -> (table.get(java.util.List.of(key)) match
          case nested: org.tomlj.TomlTable => convert(nested)
          case value => value)
      .toMap
    convert(parsed)

  private val GitMetadataLimit = 64 * 1024 // Codex's MAX_GIT_METADATA_FILE_BYTES

  /** The stripped content of a Git metadata file as Codex reads one: a regular file, not a symlink, of at most
    * GitMetadataLimit bytes. */
  private def gitMetadata(path: Path): Option[String] =
    try
      Option.when(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= GitMetadataLimit)(
        Files.readString(path).trim,
      )
    catch case _: java.io.IOException => None

  /** The directory that a `.git` file's `gitdir:` line names, as Codex reads it. */
  private def gitdirPointer(dotGit: Path): Option[Path] =
    gitMetadata(dotGit).filter(_.startsWith("gitdir:")).map(_.stripPrefix("gitdir:").trim).filter(_.nonEmpty)
      .map(dotGit.getParent.resolve)

  /** The main worktree of the linked worktree `root`, or None. Codex applies the main worktree's trust entry to the
    * worktree when the worktree has none of its own. The checks are Codex's own, in
    * `resolve_root_git_project_for_trust` (codex-rs/git-utils/src/trust.rs): Git follows symlinks and registrations
    * that Codex refuses, and a trust that Git's view granted here would offer project settings that Codex skips. */
  private def mainWorktree(root: Path): Option[Path] =
    for
      gitDir <- gitdirPointer(root.resolve(".git"))
      if !Files.isSymbolicLink(gitDir) && Files.isDirectory(gitDir)
      canonical = gitDir.toRealPath()
      if canonical.getParent.getFileName.toString == "worktrees"
      commonDir = canonical.getParent.getParent
      registered <- gitMetadata(canonical.resolve("gitdir")).filter(_.nonEmpty)
      linkedCommon <- gitMetadata(canonical.resolve("commondir")).filter(_.nonEmpty)
      registration = canonical.resolve(registered)
      if registration.getFileName.toString == ".git" && registration.getParent.toRealPath() == root.toRealPath()
      if canonical.resolve(linkedCommon).toRealPath() == commonDir
      main = gitDir.getParent.getParent.getParent
      mainGitDir <-
        val dotGit = main.resolve(".git")
        if Files.isDirectory(dotGit) then Some(dotGit) else gitdirPointer(dotGit)
      if mainGitDir.toRealPath() == commonDir
    yield main

/** `defaults claude`: the model and effort that the reviewer's session would use. That session loads no user,
  * project or local settings file, so the environment and the managed settings select both values. */
object ClaudeDefaults:

  private val Efforts = Vector("low", "medium", "high", "xhigh", "max")

  // The aliases that Claude Code documents, in its wording, and the efforts that its table gives the models the
  // aliases name on the Anthropic API (code.claude.com/docs/en/model-config). Haiku takes no effort.
  private val Models = Seq(
    ("fable", "the Fable model for your provider, for the hardest and longest-running tasks", Efforts),
    ("opus", "the latest Opus model, for complex reasoning tasks", Efforts),
    ("sonnet", "the latest Sonnet model, for daily coding tasks", Efforts),
    ("haiku", "the fast and efficient Haiku model, for simple tasks", Vector.empty),
  )

  def apply(ctx: CommandContext): JsonObject =
    val managed = managedSettings(ctx)
    def variable(name: String): Option[(String, String)] =
      managedVariable(ctx, name) match
        case Some((value, source)) => Option.when(value.nonEmpty)(value -> s"$source env") // empty unsets
        case None => ctx.env.get(name).filter(_.nonEmpty).map(_ -> name)
    val model = variable("ANTHROPIC_MODEL")
      .orElse(managed.collectFirst { case (path, settings) if settings("model").exists(_.isString) =>
        settings("model").get.asString.get -> path.toString })
      .orElse(variable("ANTHROPIC_DEFAULT_MODEL"))
    val effort = variable("CLAUDE_CODE_EFFORT_LEVEL").orElse:
      // Per-model efforts sit under canonical model names that the helper does not resolve: unknown, not guessed.
      if managed.exists(_._2.contains("modelSettings")) then None
      else managed.collectFirst { case (path, settings) if settings("effortLevel").exists(_.isString) =>
        settings("effortLevel").get.asString.get -> path.toString }
    val entry = Models.find((name, _, _) => model.exists(_._1 == name))
    JsonObject(
      "model" -> model.map(_._1).asJson,
      "effort" -> effort.map(_._1).asJson,
      "source" -> Json.obj("model" -> model.map(_._2).asJson, "effort" -> effort.map(_._2).asJson),
      "partial" -> true.asJson,
      "catalog" -> Models.map((name, description, efforts) => Json.obj("model" -> name.asJson,
        "description" -> description.asJson, "defaultEffort" -> Json.Null, "efforts" -> efforts.asJson)).asJson,
      "recommended" -> Json.obj("model" -> model.map(_._1).asJson, "effort" -> effort.map(_._1).asJson,
        "efforts" -> entry.map(_._3).asJson, "upgrade" -> Json.Null),
    )

  /** Where Claude Code reads file-based managed settings (code.claude.com/docs/en/managed-settings).
    * `KO_REVIEW_CLAUDE_MANAGED_SETTINGS` names another directory, for the tests. */
  private def managedDirectory(ctx: CommandContext): Path =
    ctx.env.get("KO_REVIEW_CLAUDE_MANAGED_SETTINGS").filter(_.nonEmpty).map(Path.of(_)).getOrElse:
      if System.getProperty("os.name").startsWith("Mac") then Path.of("/Library/Application Support/ClaudeCode")
      else Path.of("/etc/claude-code")

  /** The managed settings files, the one that Claude Code merges last first: the `.json` files of
    * `managed-settings.d` in reverse alphabetical order, hidden files left out, then `managed-settings.json`. */
  def managedSettings(ctx: CommandContext): Seq[(Path, JsonObject)] =
    val directory = managedDirectory(ctx)
    val dropIns = directory.resolve("managed-settings.d")
    val files =
      if !Files.isDirectory(dropIns) then Nil
      else
        scala.util.Using.resource(Files.list(dropIns))(_.iterator().asScala.toVector)
          .filter(path => path.getFileName.toString.endsWith(".json") && !path.getFileName.toString.startsWith("."))
          .sortBy(_.getFileName.toString).reverse
    (files :+ directory.resolve("managed-settings.json")).filter(Files.isRegularFile(_)).flatMap: path =>
      val parsed =
        try io.circe.parser.parse(Files.readString(path))
        catch case ex: java.io.IOException => Left(io.circe.ParsingFailure(ex.toString, ex))
      parsed match
        case Left(ex) => throw Claude.error("REVIEWER_CONFIG_UNREADABLE", s"$path: ${ex.getMessage}")
        case Right(json) => json.asObject.map(path -> _)

  /** The value that the highest-ranking managed `env` block naming the variable gives it, with the file that holds
    * the block. Claude Code writes such a value over the inherited one; an empty value leaves the variable unset. */
  def managedVariable(ctx: CommandContext, name: String): Option[(String, String)] =
    managedSettings(ctx).collectFirst:
      case (path, settings) if settings("env").flatMap(_.asObject).flatMap(_(name)).exists(_.isString) =>
        settings("env").get.asObject.get(name).get.asString.get -> path.toString
