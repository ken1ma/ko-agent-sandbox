package koreview

import io.circe.{Decoder, Json, JsonObject}
import io.circe.syntax.*
import java.nio.channels.{FileChannel, FileLock}
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path, StandardOpenOption}
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import scala.jdk.CollectionConverters.*
import ReviewFiles.*

/** Where reviews are kept: `worktrees/<sha256 of the worktree path>/reviews/<review id>/` under the state root. */
final class ReviewStore(val root: Path):

  def worktreeDir(worktree: Path): Path =
    root.resolve("worktrees").resolve(Observation.sha256Hex(worktree.toString.getBytes(UTF_8)))

  def reviewsDir(worktree: Path): Path = worktreeDir(worktree).resolve("reviews")

  def reviewDir(worktree: Path, id: String): Path = reviewsDir(worktree).resolve(id)

  /** Every worktree directory, whichever worktree it belongs to. */
  def worktreeDirs: Seq[Path] = listDirectory(root.resolve("worktrees"))

  /** Creates a review named by its local start minute plus a random suffix, so that directories list in start order.
    * A name already taken within the minute is drawn again. */
  def create(worktree: Path, start: StartFile): (String, Path) =
    val directory = worktreeDir(worktree)
    Files.createDirectories(directory.resolve("reviews"))
    val marker = directory.resolve("worktree.json")
    if !Files.exists(marker) then
      try write(marker, WorktreeFile(FormatVersion, now(), worktree.toString))
      catch case _: java.nio.file.FileAlreadyExistsException => () // another command wrote it meanwhile
    val random = SecureRandom()
    var created: Option[(String, Path)] = None
    while created.isEmpty do
      val id = LocalDateTime.now().format(ReviewStore.IdMinute) + "-" + f"${random.nextInt() & 0xffffffffL}%08x"
      val path = directory.resolve("reviews").resolve(id)
      try
        Files.createDirectory(path)
        created = Some(id -> path)
      catch case _: java.nio.file.FileAlreadyExistsException => ()
    Files.createDirectory(created.get._2.resolve("turns"))
    write(created.get._2.resolve("start.json"), start)
    created.get

object ReviewStore:
  val IdMinute: DateTimeFormatter = DateTimeFormatter.ofPattern("uuuu-MM-dd-HHmm")

  /** The workspace's persistent volume inside ko-agent-sandbox, and the user's state directory elsewhere. */
  def of(ctx: CommandContext): ReviewStore =
    val home = Path.of(ctx.env.getOrElse("HOME", System.getProperty("user.home")))
    val root = ctx.env.get("KO_REVIEW_STATE").filter(_.nonEmpty).map(Path.of(_)).getOrElse:
      val volume = home.resolve("persistent-volume")
      if Files.isDirectory(volume) then volume.resolve("ko-review")
      else ctx.env.get("XDG_STATE_HOME").filter(_.nonEmpty).map(Path.of(_)).getOrElse(home.resolve(".local/state"))
        .resolve("ko-review")
    ReviewStore(root)

/** An exclusive lock on a review's `review.lock`, held by one mutating command at a time. */
final class ReviewLock private (file: Path, channel: FileChannel, lock: FileLock) extends AutoCloseable:
  def close(): Unit =
    lock.release()
    channel.close()
    ReviewLock.heldHere.remove(file): Unit

object ReviewLock:
  /** The lock files that this JVM holds. The lock is a POSIX record lock, which closing any channel to the file
    * releases for the whole process, so no channel to a file in this set is opened, let alone closed. */
  private val heldHere = java.util.concurrent.ConcurrentHashMap.newKeySet[Path]()

  /** Takes the lock, or None when another command holds it. */
  def tryTake(reviewDir: Path): Option[ReviewLock] =
    val file = reviewDir.resolve("review.lock").toAbsolutePath.normalize
    if !heldHere.add(file) then None
    else
      try
        val channel = FileChannel.open(file, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        Option(channel.tryLock()) match
          case Some(lock) => Some(ReviewLock(file, channel, lock))
          case None =>
            channel.close() // this JVM held no lock on the file, so closing the channel releases none
            heldHere.remove(file)
            None
      catch
        case ex: java.io.IOException =>
          heldHere.remove(file)
          throw ex

  /** Whether a command holds the lock now. */
  def held(reviewDir: Path): Boolean =
    if !Files.exists(reviewDir.resolve("review.lock")) then false
    else tryTake(reviewDir) match
      case Some(lock) =>
        lock.close()
        false
      case None => true

/** One turn's files. */
final case class Turn(
    number: Int,
    dir: Path,
    request: RequestFile,
    thread: Option[ThreadFile],
    outcome: Option[OutcomeFile],
    escalation: Option[EscalationFile],
):
  def id: String = Turn.idOf(number)

  /** A turn is in progress while it has a request and no outcome. A helper that died during the turn leaves it so
    * too; `Review.inProgress` tells the two apart by the lock. */
  def inProgress: Boolean = outcome.isEmpty

  def result: Option[ReviewResult] = outcome.flatMap(_.result)

  def patch: Option[Path] = Some(dir.resolve("start.patch")).filter(Files.exists(_))

  def manifest: Option[ManifestFile] =
    Some(dir.resolve("manifest.json")).filter(Files.exists(_)).map(path => read[ManifestFile](path).fold(
      problem => throw ReviewError("STATE_IO_FAILED", problem), identity,
    ))

object Turn:
  def idOf(number: Int): String = f"$number%03d"

/** A review as its files hold it. Every status, the approval and the last error are computed from the files. */
final class Review(
    val id: String,
    val dir: Path,
    val worktree: Path,
    val start: StartFile,
    val turns: Vector[Turn],
    /** Whether a command other than this one holds the review's lock. */
    lockedElsewhere: Boolean,
):
  def answered: Vector[Turn] = turns.filter(_.result.isDefined)
  def lastAnswered: Option[Turn] = answered.lastOption
  def latest: Option[Turn] = turns.lastOption

  /** The approval: the result of the latest turn that the reviewer answered, when that result is APPROVED. */
  def approved: Option[Turn] = lastAnswered.filter(_.result.exists(_.disposition == "APPROVED"))

  def reviewer: Option[String] = latest.map(_.request.reviewer)
  def model: Option[String] = latest.flatMap(_.request.model)
  def effort: Option[String] = latest.flatMap(_.request.effort)
  def instructions: Option[String] = latest.flatMap(_.request.instructions)
  def threadId: Option[String] = turns.flatMap(_.thread).headOption.map(_.threadId)

  /** Whether the latest turn's reviewer is still running. A turn without an outcome whose lock nobody holds is one
    * that a helper left when it died. */
  def inProgress: Boolean = latest.exists(_.inProgress) && lockedElsewhere

  def escalated: Boolean = lastAnswered.exists(_.escalation.isDefined)

  def limitReached: Boolean = answered.size >= start.maxAnsweredTurns

  def status: String =
    if inProgress then "REVIEWING"
    else
      lastAnswered.flatMap(_.result).map(_.disposition) match
        case None => if limitReached then "LOOP_LIMIT_REACHED" else "NEW"
        case Some("USER_DECISION_REQUIRED") if escalated => "USER_DECISION_REQUIRED"
        // The coordinator can still agree that the user must decide when no reviewer turn is left.
        case Some("USER_DECISION_REQUIRED") => "USER_PROPOSED"
        case Some(disposition) if disposition != "APPROVED" && limitReached => "LOOP_LIMIT_REACHED"
        case Some(disposition) => disposition

  /** The error of the latest turn, when it failed after the last answered one. */
  def lastError: Option[JsonObject] =
    latest.filterNot(turn => lastAnswered.contains(turn)).flatMap: turn =>
      val error = turn.outcome.flatMap(_.error).orElse(Option.when(turn.inProgress && !lockedElsewhere)(
        ReviewError("HELPER_FAILED", "the helper stopped before it recorded the turn's outcome").toJson,
      ))
      error.map(JsonObject("turn" -> turn.number.asJson).deepMerge(_))

  /** The latest record's time, which expiry measures from. */
  def updatedAt: String =
    (start.writtenAt +: turns.flatMap(turn =>
      Seq(Some(turn.request.writtenAt), turn.thread.map(_.writtenAt), turn.outcome.map(_.writtenAt),
        turn.escalation.map(_.writtenAt)).flatten)).max

  /** The turns that `turn`'s start rebuilds from: its `from` chain. */
  def chain(turn: Turn): Chain =
    val patch = turn.patch.toVector
    turn.request.from match
      case Some(From(From.TurnStore, _, Some(earlier))) =>
        val previous = turns.find(_.id == earlier)
          .getOrElse(throw ReviewError("STATE_IO_FAILED", s"turn ${turn.id} starts from turn $earlier, which is gone"))
        val chained = chain(previous)
        chained.copy(patches = chained.patches ++ patch)
      case Some(From(_, commit, _)) => Chain(commit, patch)
      case None => Chain(None, patch)

  /** The `from` of a new turn: the latest turn with a start, else the commit. */
  def nextFrom(commit: Option[String]): From =
    turns.reverseIterator.find(_.patch.isDefined) match
      case Some(turn) => From(From.TurnStore, turn = Some(turn.id))
      case None => From(From.GitStore, commit = commit)

  /** A file that a newer format wrote, which this helper must not continue from: its path and version. */
  def newerFormat: Option[(Path, String)] =
    val files = dir.resolve("start.json") +: turns.flatMap: turn =>
      Seq("request.json", "thread.json", "outcome.json", "escalation.json", "manifest.json").map(turn.dir.resolve)
    files.iterator.filter(Files.exists(_)).flatMap(path => formatVersionOf(path).map(path -> _))
      .find((_, version) => ReviewFiles.newerFormat(version))

object Review:

  /** Loads the review `id` of `worktree`. `lockedElsewhere` says whether another command holds its lock. */
  def load(store: ReviewStore, worktree: Path, id: String, lockedElsewhere: Boolean): Review =
    val dir = store.reviewDir(worktree, id)
    if !Files.isDirectory(dir) || id.contains('/') || id.startsWith(".") then
      throw ReviewError("UNKNOWN_REVIEW", s"no review $id for $worktree")
    def required[T: Decoder](path: Path): T =
      read[T](path).fold(problem => throw unreadable(id, problem), identity)
    def optional[T: Decoder](path: Path): Option[T] = Option.when(Files.exists(path))(required[T](path))
    val start = required[StartFile](dir.resolve("start.json"))
    val turns = listDirectory(dir.resolve("turns"))
      .flatMap(path => path.getFileName.toString.toIntOption.map(_ -> path))
      .filter((_, path) => Files.exists(path.resolve("request.json"))) // a turn whose request was never written
      .sortBy(_._1)
      .map: (number, path) =>
        Turn(
          number,
          path,
          required[RequestFile](path.resolve("request.json")),
          optional[ThreadFile](path.resolve("thread.json")),
          optional[OutcomeFile](path.resolve("outcome.json")),
          optional[EscalationFile](path.resolve("escalation.json")),
        )
    Review(id, dir, worktree, start, turns.toVector, lockedElsewhere)

  def unreadable(id: String, problem: String): ReviewError =
    ReviewError("STATE_IO_FAILED", s"$problem: `ko-review delete $id` removes the review")

  /** Whether two instruction texts are the same, where None stands for no instructions. Whitespace around the text
    * does not count, since the skill writes the user's words to a file, which may end with a newline or not. */
  def sameInstructions(first: Option[String], second: Option[String]): Boolean =
    first.getOrElse("").strip == second.getOrElse("").strip

private[koreview] def listDirectory(directory: Path): Seq[Path] =
  if !Files.isDirectory(directory) then Nil
  else scala.util.Using.resource(Files.list(directory))(_.iterator().asScala.toVector.sortBy(_.getFileName.toString))

/** Whether an approval still covers the worktree, and if not, why not. */
final case class Freshness(fresh: Boolean, effectiveStatus: String, staleReasons: Vector[Json])

object Freshness:
  /** The approval holds for the files' raw content, the instructions it was given, and the paths that its reviewer
    * was told to look at. Staging or committing keeps it, and so does a failed turn. Moving HEAD keeps it unless a
    * path that no reviewer looked at enters the scope. */
  def of(review: Review, observation: Observation, scopes: Scopes): Freshness =
    review.approved match
      case None => Freshness(false, review.status, Vector.empty)
      case Some(turn) =>
        val manifest = turn.manifest.map(_.entries).getOrElse(Map.empty)
        val changed =
          if Observation.digestOf(manifest) == observation.contentDigest then Vector.empty
          else Observation.changes(manifest, observation.entries)
        val reviewed = turn.request.scope.toSet
        val entered = scopes.against(review.start.base.map(_.commit).orElse(observation.head))
          .filter(path => !reviewed(path) && !changed.contains(path))
        val reasons = Vector(
          Option.when(changed.nonEmpty)(reason("working files changed", changed)),
          Option.when(entered.nonEmpty)(reason("paths entered the scope since the approval", entered)),
          Option.unless(Review.sameInstructions(turn.request.instructions, review.instructions))(
            reason("the review instructions changed after the approval", Vector.empty),
          ),
        ).flatten
        Freshness(reasons.isEmpty, if reasons.isEmpty then "APPROVED" else "STALE_APPROVAL", reasons)

  private def reason(text: String, paths: Vector[String]): Json =
    Json.obj("reason" -> text.asJson, "paths" -> paths.asJson)
