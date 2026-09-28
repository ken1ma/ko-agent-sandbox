// The images this launcher owns and the build context the jar bundles for them: what they are named,
// how a built one is identified, which of them are still present, and which a newer build has
// superseded.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*
import scala.util.Using

import HostCommands.{echoCommand, fail, podman, run, runOk, Run}
import FileHelper.{readIfPresent, writePrivate}

object LauncherImages:

  /**
   * The tag of the launcher-owned base images, passed to the images built on them as IMG_TAG_VER;
   * leaf images stay on `latest` (buildCommands). It names the Debian and Temurin major versions
   * alone, so it changes when one of them does, and the next build removes the bases under the
   * previous tag (staleVersionedBaseImageTags). The full versions are in debian-temurin's
   * Containerfile alone, which sets them as image labels; the "ImgTagVersion names" test fails when
   * a major version there differs from the tag's.
   */
  val ImgTagVersion = "latest-13-25"
  def temurinImage(version: String): String = s"debian-temurin:$version"
  def coursierImage(version: String): String = s"debian-coursier:$version"
  val SandboxImage = "ko-agent-sandbox:latest"
  val ProxyImage = "ko-agent-egress-proxy:latest"
  val KoAgentFsImage = "ko-agent-fs:latest"
  val SelfTestImage = "ko-agent-self-test:latest"
  val ProxyBuildImage = "ko-agent-egress-proxy-build:cache"
  val KoAgentFsBuildImage = "ko-agent-fs-build:cache"
  val SelfTestBuildImage = "ko-agent-self-test-build:cache"

  /** In dependency order. */
  def buildImageTags(version: String): Vector[String] =
    Vector(
      temurinImage(version),
      coursierImage(version),
      SandboxImage,
      ProxyBuildImage,
      ProxyImage,
      KoAgentFsBuildImage,
      KoAgentFsImage,
    )

  /** In dependency order. */
  val SelfTestImageTags = Vector(SelfTestBuildImage, SelfTestImage)

  def managedImageTags(version: String): Vector[String] = buildImageTags(version) ++ SelfTestImageTags

  def selfTestBundleId(fsSourceId: String, selfTestSourceId: String, sandboxImageId: String): String =
    bundleSourceId(Vector(
      "ko-agent-fs" -> fsSourceId.getBytes(StandardCharsets.UTF_8),
      "ko-agent-self-test" -> selfTestSourceId.getBytes(StandardCharsets.UTF_8),
      "ko-agent-sandbox-image" -> sandboxImageId.getBytes(StandardCharsets.UTF_8),
    ))

  /**
   * The one source-identity digest, for the filter binary and the image bundle labels alike:
   * SHA-256 over (path, content) pairs in path order, each entry framed by its path, a NUL and its
   * big-endian length — the sort makes bundling order irrelevant, the length keeps file boundaries
   * unambiguous, and the path makes a rename a new identity. The algorithm is only here,
   * deliberately: a build is told the answer and repeats it, so there is no second implementation
   * to drift from this one.
   */
  def bundleSourceId(entries: Seq[(String, Array[Byte])]): String =
    val digest = MessageDigest.getInstance("SHA-256")
    entries.sortBy(_._1).foreach: (path, content) =>
      digest.update(path.getBytes(StandardCharsets.UTF_8))
      digest.update(0.toByte)
      digest.update(java.nio.ByteBuffer.allocate(8).putLong(content.length.toLong).array())
      digest.update(content)
    digest.digest().map(b => f"$b%02x").mkString

  /**
   * Digest one directory of the unpacked context — the literal build input,
   * so the id describes exactly what podman build is about to see.
   */
  def contextSourceId(context: Path, dir: String): String =
    val root = context.resolve(dir)
    val entries = Using.resource(Files.walk(root)): files =>
      files.iterator().asScala
        .filter(Files.isRegularFile(_))
        .map(file => (root.relativize(file).toString.replace('\\', '/'), Files.readAllBytes(file)))
        .toVector
    bundleSourceId(entries)

  /**
   * The digest of one bundle directory as this jar bundles it — the same
   * bytes ImageBuilds.unpackBuildContext writes and contextSourceId hashes, read
   * straight from the jar so no unpack is needed. What the filter binary's
   * `--version` must report, and what --build stamps into the sandbox and
   * proxy images as their bundle label (bundleMismatch).
   */
  def bundledSourceId(dir: String): String =
    val entries = bundleIndex()
      .filter(_.startsWith(s"$dir/"))
      .map(entry => entry.stripPrefix(s"$dir/") -> bundleResource(entry))
    bundleSourceId(entries)

  /** One entry of the build context the jar bundles (build.sbt), by its path in the context. */
  def bundleResource(name: String): Array[Byte] =
    val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
    if stream == null then
      fail(
        s"""error: the launcher jar has no bundled build-context entry '$name'
           |
           |Rebuild the launcher: sbt dist, from the repository root""".stripMargin,
      )
    try stream.readAllBytes()
    finally stream.close()

  /** The bundled build context's entries, as INDEX lists them. */
  def bundleIndex(): Vector[String] =
    String(bundleResource("INDEX"), StandardCharsets.UTF_8).linesIterator.filter(_.nonEmpty).toVector

  val BundleLabel = "ko-agent-sandbox.bundle"

  /**
   * On debian-coursier: one identity for both base directories (baseBundleId), because --update
   * builds on that image without rebuilding either base, and ImgTagVersion stays the same across
   * an update of a base's sources. The sandbox image inherits the label.
   */
  val BaseBundleLabel = "ko-agent-sandbox.base-bundle"

  def baseBundleId(temurinSourceId: String, coursierSourceId: String): String =
    bundleSourceId(Vector(
      "debian-temurin" -> temurinSourceId.getBytes(StandardCharsets.UTF_8),
      "debian-coursier" -> coursierSourceId.getBytes(StandardCharsets.UTF_8),
    ))

  /**
   * The label read back through Go's raw-string (backtick) quoting, because the argument must not
   * contain a double quote: on Windows, Java's argument encoding passes an embedded quote through
   * unescaped, and podman then parses a mangled template ("bad character U+002D"). Literal
   * newlines are avoided in the multi-line templates (AgentSandboxLauncher.PodmanInfoFormat and
   * the image inspections) for the same reason — `{{println}}` emits them on the output side
   * instead.
   */
  def labelTemplate(label: String): String = s"{{with .Config.Labels}}{{index . `$label`}}{{end}}"
  val BundleLabelTemplate = labelTemplate(BundleLabel)

  def imageLabel(podman: String, image: String, labelName: String): Run =
    run(podman, "image", "inspect", "--format", labelTemplate(labelName), image)

  /**
   * The version-lock verdict for one built image: None when its label
   * holds the jar's own digest of that image's bundled sources. The only
   * way a default-named image exists is --build, so a mismatch means a jar
   * other than this one built it — launch refuses it. An explicitly overridden
   * KO_AGENT_SANDBOX_*_IMAGE only warns: a custom image is a supported
   * case, and its interface drift still fails closed at runtime (the
   * --print-ruleset parse, the leaf's exact names).
   *
   * "container image", spelled out: the reader of this message is upgrading
   * the launcher, not thinking about images at all, and the bare name reads
   * as noise until the words say it is a container image.
   *
   * Both digests are printed because the mismatch alone cannot say which
   * side is stale — an old image, or a launch through a different jar than
   * the one that ran --build.
   */
  def bundleMismatch(
    image: String,
    expected: String,
    label: String,
    labelName: String = BundleLabel,
  ): Option[String] =
    Option.when(label.trim != expected)(
      s"container image $image was not built from the sources this launcher bundles" +
        (if label.trim.isEmpty then " (it has no bundle label)" else "") +
        "; rebuild with --build" +
        s"\n  launcher bundle digest: $expected" +
        s"\n  image label $labelName: " +
        (if label.trim.isEmpty then "(none)" else label.trim),
    )

  /**
   * --update uses a base built from this jar's bundled base sources, or does not start. The
   * identity is of the sources, not of the image's contents: the same sources install what the
   * package repositories hold on the day of the build.
   */
  def requireBaseFromBundledSources(podman: String, baseImage: String, expected: String): Unit =
    if !runOk(podman, "image", "exists", baseImage) then
      fail(s"error: base container image not found: $baseImage\n\nBuild it first: run this launcher with --build.")
    val inspected = imageLabel(podman, baseImage, BaseBundleLabel)
    if !inspected.ok then fail(s"error: could not inspect $baseImage\n${inspected.err}")
    bundleMismatch(baseImage, expected, inspected.text, BaseBundleLabel).foreach: mismatch =>
      fail(s"error: $mismatch")

  /**
   * A build's check of what it just stamped, immediately after committing the images: the
   * layer-cache staleness ImageBuilds.buildCommands describes is exactly the kind of
   * silent drift the version lock exists for, so the freshly committed labels are read back
   * rather than assumed. A failure here is podman misbehaving, not a wrong
   * jar — the remediation is clearing the build cache, not --build again.
   */
  def verifyBuiltBundleLabels(expected: Seq[(String, String)], labelName: String = BundleLabel): Unit =
    expected.foreach: (image, id) =>
      val inspected = imageLabel(podman, image, labelName)
      if !inspected.ok then
        fail(s"error: could not inspect the just-built image $image\n${inspected.err}")
      if inspected.text.trim != id then
        fail(
          s"""error: the image build committed $image with a stale bundle label
             |  launcher bundle digest: $id
             |  image label $labelName: ${
                if inspected.text.trim.isEmpty then "(none)" else inspected.text.trim}
             |
             |podman's layer cache can serve a LABEL derived from a changed
             |build arg stale (buildah #5501); this launcher passes --label to
             |bypass that cache, so this failing means podman dropped --label
             |too. Remove $image, then rerun the same launcher action.""".stripMargin,
        )

  private def localImageTag(tag: String): String = tag.stripPrefix("localhost/")

  private def imageRepository(tag: String): String =
    val normalized = localImageTag(tag)
    val separator = normalized.lastIndexOf(':')
    if separator < 0 then normalized else normalized.take(separator)

  case class TaggedImage(tag: String, id: String)

  // podman distinguishes these by case: `.Id` is the full SHA, while `.ID` is truncated.
  def imageListCommand(podman: String): Vector[String] =
    Vector(podman, "image", "ls", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}}\t{{.Id}}")

  def existingImageTags(podman: String, failure: String = "build did not start"): Vector[TaggedImage] =
    val listed = run(imageListCommand(podman)*)
    if !listed.ok then fail(s"error: $failure; could not list images\n${listed.err}")
    listed.text.linesIterator.flatMap: line =>
      line.split('\t') match
        case Array(tag, id) if tag.nonEmpty && id.nonEmpty => Some(TaggedImage(tag, id))
        case _ => fail(s"error: $failure; podman returned an unrecognized image listing line: $line")
    .toVector

  def imageIdsForTags(existing: Vector[TaggedImage], images: Vector[String]): Vector[String] =
    val byTag = existing.map(image => localImageTag(image.tag) -> image.id).toMap
    images.flatMap(image => byTag.get(localImageTag(image)))

  def requiredImageId(existing: Vector[TaggedImage], image: String, failure: String): String =
    imageIdsForTags(existing, Vector(image)).headOption.getOrElse:
      fail(s"error: $failure; could not find the image id for $image")

  /**
   * Only the launcher-owned base repositories have versioned tags. Fixed leaf and cache tags are
   * deliberately excluded: a supported custom sandbox or proxy image may use another tag in the
   * same repository. Leaves precede bases. `localhost/` is podman's display form for the unqualified
   * names the launcher passes to `build -t`.
   */
  def staleVersionedBaseImageTags(
    existing: Vector[TaggedImage],
    current: Vector[String],
  ): Vector[TaggedImage] =
    val versionedRepositories = Set("debian-temurin", "debian-coursier")
    val currentTags = current.map(localImageTag).toSet
    val repositoryOrder = current.map(imageRepository).zipWithIndex.toMap
    existing.distinctBy(_.tag)
      .filter: image =>
        val normalized = localImageTag(image.tag)
        versionedRepositories.contains(imageRepository(normalized)) && !currentTags.contains(normalized)
      .sortBy(image => -repositoryOrder(imageRepository(image.tag)))

  /**
   * The self-test images a listing holds, in removal order: SelfTestImageTags reversed, leaves
   * before bases like every other cleanup list. podman's listing order is not a dependency order,
   * so it is never inherited.
   */
  def selfTestCleanupOrder(existing: Vector[TaggedImage]): Vector[TaggedImage] =
    val removalOrder = SelfTestImageTags.reverse.zipWithIndex.toMap
    existing.distinctBy(_.tag)
      .filter(image => removalOrder.contains(localImageTag(image.tag)))
      .sortBy(image => removalOrder(localImageTag(image.tag)))

  /** On-demand self-test outputs whose current-looking tags belong to another bundle. */
  def staleSelfTestImages(
    podman: String,
    existing: Vector[TaggedImage],
    expectedBundleId: String,
  ): Vector[TaggedImage] =
    selfTestCleanupOrder(existing).filter: image =>
      val inspected = run(podman, "image", "inspect", "--format", BundleLabelTemplate, image.id)
      if !inspected.ok then fail(s"error: could not inspect ${image.tag} before the build\n${inspected.err}")
      inspected.text.trim != expectedBundleId

  private val FullImageId = "(?:sha256:)?[0-9a-f]{64}".r

  /** An image or container id at podman's own listing width; `image ls` and `inspect` may
    * prefix it with `sha256:`, which the listing does not show. */
  def shortId(id: String): String = id.stripPrefix("sha256:").take(12)

  private def imageCleanupJournalEntries(path: Path): Vector[String] =
    readIfPresent(path).toVector.flatMap(_.linesIterator.map(_.trim).filter(_.nonEmpty))

  def validateImageCleanupIds(path: Path, ids: Vector[String]): Either[String, Vector[String]] =
    ids.find(id => !FullImageId.matches(id)) match
      case Some(id) =>
        Left(
          s"error: invalid image id in cleanup journal $path: $id\n" +
            "Run --reset-all to discard malformed entries while retaining valid pending cleanup.",
        )
      case None     => Right(ids.distinct)

  def readImageCleanupJournal(path: Path): Either[String, Vector[String]] =
    validateImageCleanupIds(path, imageCleanupJournalEntries(path))

  def writeImageCleanupJournal(path: Path, ids: Vector[String]): Unit =
    val validated = validateImageCleanupIds(path, ids).fold(fail(_), identity)
    if validated.isEmpty then Files.deleteIfExists(path)
    else writePrivate(path, validated.mkString("", "\n", "\n"))

  /** Drop only malformed entries; valid ids remain the ownership record for the next build. */
  def repairImageCleanupJournal(path: Path): Vector[String] =
    val entries = imageCleanupJournalEntries(path)
    val (valid, invalid) = entries.partition(FullImageId.matches)
    if invalid.nonEmpty then
      System.err.println(s"discarding ${invalid.size} malformed entry(s) from image cleanup journal: $path")
      writeImageCleanupJournal(path, valid)
    invalid

  /**
   * The cleanup order recorded before a build mutates any tag: an interrupted run's unfinished
   * ids first, then this run's leaves before bases and stale named bases.
   *
   * Pulled images are deliberately absent: their names and lifecycle belong to their publishers,
   * and another local workload may use an older revision after the launcher refreshes the tag.
   */
  def imageCleanupCandidates(
    pending: Vector[String],
    before: Vector[String],
    staleTags: Vector[TaggedImage],
  ): Vector[String] =
    (pending ++ before.reverse ++ staleTags.map(_.id)).distinct

  /** Newly discovered child images must precede the parent candidates they keep alive. */
  def prependImageCleanupDependents(
    candidates: Vector[String],
    dependents: Vector[TaggedImage],
  ): Vector[String] = (dependents.map(_.id) ++ candidates).distinct

  def prepareImageCleanupJournal(
    path: Path,
    before: Vector[String],
    staleTags: Vector[TaggedImage],
  ): Vector[String] =
    val pending = readImageCleanupJournal(path).fold(fail(_), identity)
    val candidates = imageCleanupCandidates(pending, before, staleTags)
    writeImageCleanupJournal(path, candidates)
    candidates

  /**
   * Classify self-test tags only after a build has committed the sandbox tag they should inherit.
   * Extend the journal before returning them to the caller for untagging or removal.
   */
  def includeStaleSelfTestCleanup(
    podman: String,
    journal: Path,
    initialCandidates: Vector[String],
    staleBaseTags: Vector[TaggedImage],
    fsSourceId: String,
    selfTestSourceId: String,
  ): (Vector[String], Vector[TaggedImage]) =
    val currentTags = existingImageTags(podman, "cleanup did not start")
    val sandboxImageId = requiredImageId(
      currentTags,
      SandboxImage,
      "cleanup did not start",
    )
    val selfTestId = selfTestBundleId(fsSourceId, selfTestSourceId, sandboxImageId)
    val staleSelfTestTags = staleSelfTestImages(podman, currentTags, selfTestId)
    val candidates = prependImageCleanupDependents(initialCandidates, staleSelfTestTags)
    writeImageCleanupJournal(journal, candidates)
    candidates -> (staleSelfTestTags ++ staleBaseTags)

  def supersededImageRemoveCommands(
    podman: String,
    candidates: Vector[String],
    current: Vector[String],
  ): Vector[Vector[String]] =
    val currentIds = current.toSet
    candidates.distinct.filterNot(currentIds).map: id =>
      Vector(podman, "image", "rm", "--ignore", id)

  def protectedImageNames(
    imageNames: Vector[String],
    staleTags: Vector[TaggedImage],
  ): Vector[String] =
    val staleNames = staleTags.map(image => localImageTag(image.tag)).toSet
    imageNames.filterNot(image => staleNames.contains(localImageTag(image)))

  private val ImageUsingContainer =
    "(?i)image used by ([0-9a-f]{12,64}): image is in use by a container".r

  /**
   * The continuation line is indented under the note, as every launcher line starts with a label and
   * an unindented bare line reads as a subprocess's. The second form's continuation is podman's
   * error text, so it stays as podman wrote it.
   */
  def supersededImageRetentionNote(imageId: String, error: String): String =
    ImageUsingContainer.findFirstMatchIn(error) match
      case Some(matched) =>
        s"note: keeping superseded image ${shortId(imageId)} while container ${shortId(matched.group(1))}"
          + " still uses it;\n  a later --build, --update, or --self-test will retry once that container is gone"
      case None =>
        s"note: keeping superseded image ${shortId(imageId)}; podman did not remove it\n${error.trim}"

  def removeSupersededImages(
    podman: String,
    candidates: Vector[String],
    imageNames: Vector[String],
    staleTags: Vector[TaggedImage],
  ): Vector[String] =
    val current = imageIdsForTags(
      existingImageTags(podman, "cleanup did not start"),
      protectedImageNames(imageNames, staleTags),
    )
    val currentIds = current.toSet
    staleTags.filterNot(image => currentIds.contains(image.id)).foreach: image =>
      val command = Vector(podman, "image", "untag", image.id, image.tag)
      System.err.println(s"removing launcher tag from an older build: ${image.tag}")
      echoCommand(command)
      val untagged = run(command*)
      if !untagged.ok then
        System.err.println(s"note: keeping stale launcher tag ${image.tag}\n${untagged.err}")
    val remaining = Vector.newBuilder[String]
    supersededImageRemoveCommands(podman, candidates, current).foreach: command =>
      System.err.println(s"removing launcher image from an older build: ${command.last}")
      echoCommand(command)
      val removed = run(command*)
      if !removed.ok then
        remaining += command.last
        System.err.println(supersededImageRetentionNote(command.last, removed.err))
    remaining.result()
