package koreview

import io.circe.{Decoder, Encoder, JsonObject, Printer}
import io.circe.derivation.{Configuration, ConfiguredCodec}
import io.circe.parser.decode
import io.circe.syntax.*
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{FileAlreadyExistsException, Files, Path}
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.ZoneOffset

/** The JSON files that hold a review, one class per file. ko-review/doc/design.md, "Where the state is", lays the
  * files out.
  *
  * The files change across helper versions by these rules, so that a review stays readable:
  *
  * 1. A file is never edited; a new fact is a new file.
  * 2. A reader ignores files and fields it does not know.
  * 3. A missing field means the default that its class declares. A field added later declares a default true of every
  *    older file, or one that the rules treat as unproven.
  * 4. A field or a file keeps its meaning. A new meaning gets a new name, never a version suffix, and a removed name is
  *    never reused.
  * 5. Every file carries `formatVersion`, the semantic version of the format it follows. Until 1.0.0, a newer patch
  *    version only adds fields that an older helper may ignore, and a newer minor version makes an older helper refuse
  *    to continue the review (`newerFormat`). Read-only commands work at any version.
  *
  * A change to these classes changes the format: bump `FormatVersion`, and add samples under the new version for
  * ReviewFilesTest.
  */
object ReviewFiles:

  val FormatVersion = "0.2.0"

  given Configuration = Configuration.default.withDefaults

  /** `worktrees/<sha256 of the path>/worktree.json`: the path that the directory's name hashes. */
  final case class WorktreeFile(formatVersion: String, writtenAt: String, worktree: String) derives ConfiguredCodec

  /** A commit that a ref named, in the store that holds it. */
  final case class Base(store: String = "git", ref: String, commit: String) derives ConfiguredCodec

  /** `start.json`: what holds for the whole review. The reviewer, model and effort are each turn's. */
  final case class StartFile(
      formatVersion: String,
      writtenAt: String,
      base: Option[Base] = None,
      maxAnsweredTurns: Int = 12,
      timeoutSeconds: Int = 3600,
  ) derives ConfiguredCodec

  /** What a turn's `start.patch` applies to: a commit in Git, or an earlier turn's start. Without a commit, the start
    * is an empty tree, as under an unborn HEAD. */
  final case class From(store: String, commit: Option[String] = None, turn: Option[String] = None)
      derives ConfiguredCodec

  object From:
    val GitStore = "git"
    val TurnStore = "ko-review:turn"

  /** The session that ran a turn's command, as its environment tells: the tool, `claude` or `codex`, and what that tool
    * exports. A fact the environment does not give is absent; the model is never given (ko-review/doc/design.md, "The
    * coordinator's record"). */
  final case class Coordinator(
      tool: String,
      sessionId: Option[String] = None,
      version: Option[String] = None,
      effort: Option[String] = None,
  ) derives ConfiguredCodec

  /** `turns/NNN/request.json`, written before the reviewer runs. */
  final case class RequestFile(
      formatVersion: String,
      writtenAt: String,
      reviewer: String,
      model: Option[String] = None,
      effort: Option[String] = None,
      reviewerVersion: Option[String] = None,
      pluginVersion: Option[String] = None,
      /** The user's instructions in force for this turn. */
      instructions: Option[String] = None,
      /** The author's message. */
      message: String,
      /** The paths that the reviewer is told to look at. */
      scope: Vector[String] = Vector.empty,
      from: Option[From] = None,
      /** None when the command ran outside Claude Code and Codex, as by hand. */
      coordinator: Option[Coordinator] = None,
  ) derives ConfiguredCodec

  /** `turns/NNN/thread.json`, only in a turn that opened a thread, written the moment the reviewer names it. */
  final case class ThreadFile(formatVersion: String, writtenAt: String, threadId: String) derives ConfiguredCodec

  final case class Finding(
      id: String,
      severity: String,
      location: Option[String],
      description: String,
      evidence: String,
  ) derives ConfiguredCodec

  final case class Suggestion(id: String, kind: String, location: Option[String], description: String, reason: String)
      derives ConfiguredCodec

  final case class UserDecision(
      issue: String,
      reviewerPosition: String,
      whyTechnicalEvidenceCannotDecide: String,
      decisionRequested: String,
  ) derives ConfiguredCodec

  /** The reviewer's result, as the helper validated it against schemas/review-result.schema.json. */
  final case class ReviewResult(
      disposition: String,
      summary: String,
      findings: Vector[Finding] = Vector.empty,
      suggestions: Vector[Suggestion] = Vector.empty,
      userDecision: Option[UserDecision] = None,
  ) derives ConfiguredCodec

  /** `turns/NNN/outcome.json`, written when the turn ends: the reviewer's exit status when the reviewer ran, and its
    * validated result or the helper's error. */
  final case class OutcomeFile(
      formatVersion: String,
      writtenAt: String,
      exitStatus: Option[Int] = None,
      result: Option[ReviewResult] = None,
      error: Option[JsonObject] = None,
  ) derives ConfiguredCodec

  /** `turns/NNN/escalation.json`, written when the coordinator agrees that the user must decide the turn's request. */
  final case class EscalationFile(formatVersion: String, writtenAt: String, message: String) derives ConfiguredCodec

  /** `turns/NNN/manifest.json`: the hash of every reviewable file's entry at the turn's start. `repositories` names
    * the entries that are nested repositories. */
  final case class ManifestFile(
      formatVersion: String,
      writtenAt: String,
      entries: Map[String, String] = Map.empty,
      repositories: Vector[String] = Vector.empty,
  ) derives ConfiguredCodec

  /** The current time as every file records it: UTC with milliseconds, so that the text sorts as the time does. */
  def now(): String = timeText(Instant.now())

  def timeText(instant: Instant): String = TimeFormat.format(instant)

  def parseTime(text: String): Option[Instant] =
    try Some(Instant.from(TimeFormat.parse(text)))
    catch case _: java.time.format.DateTimeParseException => None

  private val TimeFormat = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSXXX").withZone(ZoneOffset.UTC)

  private val FilePrinter = Printer.spaces2.copy(dropNullValues = true, colonLeft = "")

  /** Writes `value` to `path`, which must not exist. The file goes to a temporary name first and is linked to its
    * name, so a reader never sees part of it, and a second write fails instead of replacing it. */
  def write[T: Encoder](path: Path, value: T): Unit = writeBytes(path, (FilePrinter.print(value.asJson) + "\n")
    .getBytes(UTF_8))

  def writeBytes(path: Path, bytes: Array[Byte]): Unit =
    val temporary = Files.createTempFile(path.getParent, path.getFileName.toString + ".", ".tmp")
    try
      Files.write(temporary, bytes)
      try Files.createLink(path, temporary)
      catch
        case ex: FileAlreadyExistsException => throw ex
        case _: UnsupportedOperationException | _: java.io.IOException =>
          // A file system without hard links: the move checks for an existing file first, not atomically.
          if Files.exists(path) then throw FileAlreadyExistsException(path.toString)
          Files.move(temporary, path)
    finally Files.deleteIfExists(temporary): Unit

  /** Reads `path` as a `T`, or explains why it cannot. */
  def read[T: Decoder](path: Path): Either[String, T] =
    try decode[T](Files.readString(path)).left.map(ex => s"$path cannot be read: ${ex.getMessage}")
    catch case ex: java.io.IOException => Left(s"$path cannot be read: $ex")

  /** Whether `version` is newer than `FormatVersion` in its major or minor part, which makes this helper refuse to
    * continue the review. A version that does not parse counts as newer. */
  def newerFormat(version: String): Boolean =
    def parts(text: String) = text.split('.').toVector.map(_.toIntOption)
    (parts(version), parts(FormatVersion)) match
      case (Vector(Some(major), Some(minor), Some(_)), Vector(Some(ourMajor), Some(ourMinor), Some(_))) =>
        major > ourMajor || (major == ourMajor && minor > ourMinor)
      case _ => true

  /** The `formatVersion` of a JSON file, whatever else it holds. */
  def formatVersionOf(path: Path): Option[String] =
    try io.circe.parser.parse(Files.readString(path)).toOption.flatMap(_.hcursor.get[String]("formatVersion").toOption)
    catch case _: java.io.IOException => None
