// The images this launcher owns: what they are named, how a built one is identified, which of them
// are still present, and which a newer build has superseded.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}

import HostCommands.{fail, readIfPresent, run, writePrivate}
import KoAgentFs.bundleSourceId

object LauncherImages:

  /**
   * The Debian/Temurin base the two base images pin, passed to every image
   * as IMG_TAG_VER; leaf images stay on `latest` (buildCommands). Mirrors
   * the pins in debian-temurin's Containerfile — a bump edits both files,
   * and the "ImgTagVersion mirrors" test fails when they disagree.
   */
  val ImgTagVersion = "13.6-25.0.4-0"
  val ProxyBuildImage = "ko-agent-egress-proxy-build:cache"
  val KoAgentFsBuildImage = "ko-agent-fs-build:cache"
  val SelfTestBuildImage = "ko-agent-self-test-build:cache"

  /** Every image tag whose lifecycle belongs to --build, in dependency order. */
  def buildImageTags(version: String): Vector[String] =
    Vector(
      s"debian-temurin:$version",
      s"debian-coursier:$version",
      "ko-agent-sandbox:latest",
      ProxyBuildImage,
      "ko-agent-egress-proxy:latest",
      KoAgentFsBuildImage,
      "ko-agent-fs:latest"
    )

  /** The two image tags whose lifecycle belongs to --self-test, in dependency order. */
  val SelfTestImageTags = Vector(SelfTestBuildImage, "ko-agent-self-test:latest")

  /** Every tag an image build must protect while replaying an interrupted cleanup. */
  def managedImageTags(version: String): Vector[String] = buildImageTags(version) ++ SelfTestImageTags

  /** Identity of the self-test sources and the sandbox image they actually inherit. */
  def selfTestBundleId(fsSourceId: String, selfTestSourceId: String, sandboxImageId: String): String =
    bundleSourceId(Vector(
      "ko-agent-fs" -> fsSourceId.getBytes(StandardCharsets.UTF_8),
      "ko-agent-self-test" -> selfTestSourceId.getBytes(StandardCharsets.UTF_8),
      "ko-agent-sandbox-image" -> sandboxImageId.getBytes(StandardCharsets.UTF_8)
    ))

  val BundleLabel = "ko-agent-sandbox.bundle"

  /**
   * The label read back through Go's raw-string (backtick) quoting, because the argument must not
   * carry a double quote: on Windows, Java's argument encoding passes an embedded quote through
   * unescaped, and podman then parses a mangled template ("bad character U+002D"). Literal
   * newlines are avoided in the multi-line templates below for the same reason — `{{println}}`
   * emits them on the output side instead.
   */
  val BundleLabelTemplate = s"{{with .Config.Labels}}{{index . `$BundleLabel`}}{{end}}"

  private def localImageTag(tag: String): String = tag.stripPrefix("localhost/")

  private def imageRepository(tag: String): String =
    val normalized = localImageTag(tag)
    val separator = normalized.lastIndexOf(':')
    if separator < 0 then normalized else normalized.take(separator)

  case class TaggedImage(tag: String, id: String)

  // Podman distinguishes these by case: `.Id` is the full SHA, while `.ID` is truncated.
  def imageListCommand(podman: String): Vector[String] =
    Vector(podman, "image", "ls", "--no-trunc", "--format", "{{.Repository}}:{{.Tag}}\t{{.Id}}")

  /** All named images, including tags from older launcher versions. */
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
   * Old launcher versions varied only the two base repositories' tags. The fixed leaf and cache
   * tags are deliberately excluded: a supported custom sandbox or proxy image may use another tag
   * in the same repository. Leaves precede bases. `localhost/` is Podman's display form for the
   * unqualified names the launcher passes to `build -t`.
   */
  def staleVersionedBaseImageTags(
    existing: Vector[TaggedImage],
    current: Vector[String]
  ): Vector[TaggedImage] =
    val versionedRepositories = Set("debian-temurin", "debian-coursier")
    val currentTags = current.map(localImageTag).toSet
    val repositoryOrder = current.map(imageRepository).zipWithIndex.toMap
    existing.distinctBy(_.tag)
      .filter: image =>
        val normalized = localImageTag(image.tag)
        versionedRepositories.contains(imageRepository(normalized)) && !currentTags.contains(normalized)
      .sortBy(image => -repositoryOrder(imageRepository(image.tag)))

  /** On-demand self-test outputs whose current-looking tags belong to another bundle. */
  def staleSelfTestImages(
    podman: String,
    existing: Vector[TaggedImage],
    expectedBundleId: String
  ): Vector[TaggedImage] =
    val selfTestTags = SelfTestImageTags.toSet
    existing.filter(image => selfTestTags.contains(localImageTag(image.tag))).filter: image =>
        val inspected = run(podman, "image", "inspect", "--format", BundleLabelTemplate, image.id)
        if !inspected.ok then fail(s"error: could not inspect ${image.tag} before the build\n${inspected.err}")
        inspected.text.trim != expectedBundleId

  private val FullImageId = "(?:sha256:)?[0-9a-f]{64}".r

  private def imageCleanupJournalEntries(path: Path): Vector[String] =
    readIfPresent(path).toVector.flatMap(_.linesIterator.map(_.trim).filter(_.nonEmpty))

  def validateImageCleanupIds(path: Path, ids: Vector[String]): Either[String, Vector[String]] =
    ids.find(id => !FullImageId.matches(id)) match
      case Some(id) =>
        Left(
          s"error: invalid image id in cleanup journal $path: $id\n" +
            "Run --reset-all to discard malformed entries while retaining valid pending cleanup."
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
    staleTags: Vector[TaggedImage]
  ): Vector[String] =
    (pending ++ before.reverse ++ staleTags.map(_.id)).distinct

  /** Newly discovered child images must precede the parent candidates they keep alive. */
  def prependImageCleanupDependents(
    candidates: Vector[String],
    dependents: Vector[TaggedImage]
  ): Vector[String] = (dependents.map(_.id) ++ candidates).distinct

  def prepareImageCleanupJournal(
    path: Path,
    before: Vector[String],
    staleTags: Vector[TaggedImage]
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
    selfTestSourceId: String
  ): (Vector[String], Vector[TaggedImage]) =
    val currentTags = existingImageTags(podman, "cleanup did not start")
    val sandboxImageId = requiredImageId(
      currentTags,
      "ko-agent-sandbox:latest",
      "cleanup did not start"
    )
    val selfTestId = selfTestBundleId(fsSourceId, selfTestSourceId, sandboxImageId)
    val staleSelfTestTags = staleSelfTestImages(podman, currentTags, selfTestId)
    val candidates = prependImageCleanupDependents(initialCandidates, staleSelfTestTags)
    writeImageCleanupJournal(journal, candidates)
    candidates -> (staleSelfTestTags ++ staleBaseTags)

  def supersededImageRemoveCommands(
    podman: String,
    candidates: Vector[String],
    current: Vector[String]
  ): Vector[Vector[String]] =
    val currentIds = current.toSet
    candidates.distinct.filterNot(currentIds).map: id =>
      Vector(podman, "image", "rm", "--ignore", id)

  def protectedImageNames(
    imageNames: Vector[String],
    staleTags: Vector[TaggedImage]
  ): Vector[String] =
    val staleNames = staleTags.map(image => localImageTag(image.tag)).toSet
    imageNames.filterNot(image => staleNames.contains(localImageTag(image)))

  private val ImageUsingContainer =
    "(?i)image used by ([0-9a-f]{12,64}): image is in use by a container".r

  def supersededImageRetentionNote(imageId: String, error: String): String =
    ImageUsingContainer.findFirstMatchIn(error) match
      case Some(matched) =>
        s"note: keeping superseded image $imageId while container ${matched.group(1)} still uses it;\n" +
          "a later --build, --update, or --self-test will retry after that container is removed"
      case None =>
        s"note: keeping superseded image $imageId; Podman did not remove it\n${error.trim}"

  def removeSupersededImages(
    podman: String,
    candidates: Vector[String],
    imageNames: Vector[String],
    staleTags: Vector[TaggedImage]
  ): Vector[String] =
    val current = imageIdsForTags(
      existingImageTags(podman, "cleanup did not start"),
      protectedImageNames(imageNames, staleTags)
    )
    val currentIds = current.toSet
    staleTags.filterNot(image => currentIds.contains(image.id)).foreach: image =>
      val command = Vector(podman, "image", "untag", image.id, image.tag)
      System.err.println(s"removing launcher tag from an older build: ${image.tag}")
      System.err.println(command.mkString(" "))
      val untagged = run(command*)
      if !untagged.ok then
        System.err.println(s"note: keeping stale launcher tag ${image.tag}\n${untagged.err}")
    val remaining = Vector.newBuilder[String]
    supersededImageRemoveCommands(podman, candidates, current).foreach: command =>
      System.err.println(s"removing launcher image from an older build: ${command.last}")
      System.err.println(command.mkString(" "))
      val removed = run(command*)
      if !removed.ok then
        remaining += command.last
        System.err.println(supersededImageRetentionNote(command.last, removed.err))
    remaining.result()
