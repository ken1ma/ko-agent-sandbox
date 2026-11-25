package koreview

import io.circe.{Json, JsonObject}
import io.circe.syntax.*
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}
import java.time.{Duration, Instant, LocalDateTime, ZoneId}
import ReviewFiles.*

/** The helper's commands. Each returns the JSON object it prints, or prints itself and returns None. */
final class Commands(ctx: CommandContext):

  // Claude Code's default cleanupPeriodDays: a Claude reviewer's session transcripts, which hold each turn's exact
  // prompt, are gone after that, so the review goes with them.
  private val RetentionDays = 30

  /** The review that the command created or opened, which a failure names. */
  var current: Option[(ReviewStore, Path, String)] = None

  private lazy val git = ctx.git
  private lazy val store = ReviewStore.of(ctx)

  def start(
      reviewerName: String,
      messageFile: String,
      instructionsFile: Option[String],
      baseRef: Option[String],
      model: Option[String],
      effort: Option[String],
      maxAnsweredTurns: Int,
      timeoutSeconds: Int,
  ): JsonObject =
    val reviewer = Reviewer.named(reviewerName).get
    val root = worktreeRoot()
    val message = readMessage(messageFile)
    val instructions = instructionsFile.map(readMessage)
    val base = baseRef.map(resolveBase(root, _))
    checkScope(root, base)
    reviewer.checkChoice(ctx, effort)
    val program = preconditions(reviewer)
    val (expired, failures) = expire()
    val (id, dir) = store.create(root, StartFile(
      FormatVersion,
      now(),
      base,
      maxAnsweredTurns,
      timeoutSeconds,
    ))
    current = Some((store, root, id))
    withLock(dir, id): () =>
      val review = Review.load(store, root, id, lockedElsewhere = false)
      runTurn(root, review, reviewer, program, model, effort, instructions, message)
        .add("expiredReviews", expired.asJson).add("expiryFailures", failures.asJson)

  def continueReview(id: String, messageFile: String, instructionsFile: Option[String]): JsonObject =
    val root = worktreeRoot()
    val message = readMessage(messageFile)
    val instructions = instructionsFile.map(readMessage)
    val dir = existingReview(root, id)
    withLock(dir, id): () =>
      val review = Review.load(store, root, id, lockedElsewhere = false)
      current = Some((store, root, id))
      val reviewer = mutableReviewer(review)
      val program = preconditions(reviewer)
      runTurn(root, review, reviewer, program, review.model, review.effort, instructions.orElse(review.instructions),
        message)

  def escalate(id: String, messageFile: String): JsonObject =
    val root = worktreeRoot()
    val message = readMessage(messageFile)
    val dir = existingReview(root, id)
    withLock(dir, id): () =>
      val review = Review.load(store, root, id, lockedElsewhere = false)
      current = Some((store, root, id))
      mutableReviewer(review)
      if review.status != "USER_PROPOSED" then
        throw ReviewError(
          "ESCALATION_NOT_PROPOSED",
          s"review $id is ${review.status}: escalate only after ${review.reviewer.getOrElse("the reviewer")} asked" +
            " for the user's decision",
        )
      write(review.lastAnswered.get.dir.resolve("escalation.json"), EscalationFile(FormatVersion, now(), message))
      summaryOf(root, id)

  def checkApproval(id: String): JsonObject =
    val root = worktreeRoot()
    val summary = summaryOf(root, id)
    if !summary("effectiveStatus").flatMap(_.asString).contains("APPROVED") then
      throw ReviewError(
        "NOT_APPROVED",
        s"review $id is ${summary("effectiveStatus").flatMap(_.asString).getOrElse("")}, not an approval of the" +
          " current tree",
        summary,
      )
    summary

  def show(id: String): JsonObject = summaryOf(worktreeRoot(), id)

  def list(): JsonObject =
    val root = worktreeRoot()
    val observation = Observation.observe(git, root) // one scan for every review's freshness
    val scopes = Scopes(git, root)
    val rows = listDirectory(store.reviewsDir(root)).map: dir =>
      val id = dir.getFileName.toString
      try
        val review = Review.load(store, root, id, ReviewLock.held(dir))
        val freshness = Freshness.of(review, observation, scopes)
        Json.obj(
          "reviewId" -> id.asJson,
          "reviewer" -> review.reviewer.asJson,
          "effectiveStatus" -> freshness.effectiveStatus.asJson,
          "turn" -> review.latest.map(_.number).getOrElse(0).asJson,
          "approvalFresh" -> freshness.fresh.asJson,
          "createdAt" -> review.start.writtenAt.asJson,
          "updatedAt" -> review.updatedAt.asJson,
        )
      catch
        case ex: ReviewError =>
          // A review that this helper cannot read is still listed, so that its id can be given to `delete`.
          def field(path: Path, key: String) =
            try io.circe.parser.parse(Files.readString(path)).toOption.flatMap(_.hcursor.get[String](key).toOption)
            catch case _: java.io.IOException => None
          val turns = listDirectory(dir.resolve("turns"))
          Json.obj(
            "reviewId" -> id.asJson,
            "reviewer" -> turns.headOption.flatMap(turn => field(turn.resolve("request.json"), "reviewer")).asJson,
            "effectiveStatus" -> ex.code.asJson,
            "turn" -> turns.size.asJson,
            "approvalFresh" -> false.asJson,
            "createdAt" -> field(dir.resolve("start.json"), "writtenAt").asJson,
            "updatedAt" -> Json.Null,
          )
    val sorted = rows.sortBy: row =>
      (row.hcursor.get[String]("createdAt").getOrElse(""), row.hcursor.get[String]("reviewId").getOrElse(""))
    JsonObject("worktree" -> root.toString.asJson, "reviews" -> sorted.asJson)

  /** The approved reviews whose approval still covers part of the scope that a `start` with this base would have,
    * newest approval first. A path is covered when the approved turn's reviewer was told to look at it and its content
    * is the approved content. A candidate has the base and the instructions that the new review would have. */
  def approvals(baseRef: Option[String], instructionsFile: Option[String]): JsonObject =
    val root = worktreeRoot()
    val base = baseRef.map(resolveBase(root, _))
    val instructions = instructionsFile.map(readMessage)
    val observation = Observation.observe(git, root)
    val scopes = Scopes(git, root)
    val scope = scopes.against(base.map(_.commit).orElse(observation.head))
    val rows = listDirectory(store.reviewsDir(root)).flatMap: dir =>
      try
        val review = Review.load(store, root, dir.getFileName.toString, ReviewLock.held(dir))
        review.approved.filter: turn =>
          review.start.base.map(_.commit) == base.map(_.commit) &&
            // The approval's own instructions decide what it covers, and the review's decide what a continuation
            // uses. They differ after a failed turn that brought new instructions.
            Review.sameInstructions(turn.request.instructions, instructions) &&
            Review.sameInstructions(review.instructions, instructions)
        .flatMap: turn =>
          val manifest = turn.manifest.map(_.entries).getOrElse(Map.empty)
          val reviewed = turn.request.scope.toSet
          val covered = scope.filter(path => reviewed(path) && observation.entries.get(path) == manifest.get(path))
          Option.when(covered.nonEmpty):
            val at = turn.outcome.get.writtenAt
            at -> Json.obj(
              "reviewId" -> review.id.asJson,
              "reviewer" -> review.reviewer.asJson,
              "model" -> review.model.asJson,
              "effort" -> review.effort.asJson,
              "turn" -> turn.number.asJson,
              "approvedAt" -> at.asJson,
              "approvalFresh" -> Freshness.of(review, observation, scopes).fresh.asJson,
              "coveredPaths" -> covered.asJson,
              "newPaths" -> scope.filterNot(covered.contains).asJson,
            )
      catch case _: ReviewError => None
    JsonObject(
      "worktree" -> root.toString.asJson,
      "base" -> base.asJson,
      "scopePaths" -> scope.asJson,
      "approvals" -> rows.sortBy((at, row) => (at, row.hcursor.get[String]("reviewId").getOrElse(""))).reverse.map(_._2)
        .asJson,
    )

  def transcript(id: String, turnNumber: Option[Int]): Option[JsonObject] =
    val root = worktreeRoot()
    val review = Review.load(store, root, id, ReviewLock.held(existingReview(root, id)))
    current = Some((store, root, id))
    val display = review.reviewer.flatMap(Reviewer.named).map(_.display).orElse(review.reviewer).getOrElse("Reviewer")
    turnNumber match
      case Some(number) =>
        val turn = review.turns.find(_.number == number)
          .getOrElse(throw ReviewError("UNKNOWN_TURN", s"review $id has no turn $number"))
        ctx.out.print(Transcript.turn(review, display, turn))
      case None =>
        val freshness = Freshness.of(review, Observation.observe(git, root), Scopes(git, root))
        ctx.out.print(Transcript.review(review, display, freshness.effectiveStatus, inspectLines(review)))
    None

  /** Prints `git diff` between two turns' starts, or between a turn's start and the working tree, rebuilt from the
    * patches. The paths that the patches leave out are named on stderr when their manifest hashes differ. */
  def diff(id: String, fromTurn: Option[Int], toTurn: Option[Int], gitOptions: Seq[String]): Option[JsonObject] =
    val root = worktreeRoot()
    val review = {
      existingReview(root, id)
      Review.load(store, root, id, lockedElsewhere = false)
    }
    current = Some((store, root, id))
    def started(number: Int) = review.turns.find(turn => turn.number == number && turn.patch.isDefined)
      .getOrElse(throw ReviewError("UNKNOWN_TURN", s"review $id has no turn $number with a recorded start"))
    val from = fromTurn.map(started).orElse(review.approved.filter(_.patch.isDefined))
      .orElse(review.turns.reverseIterator.find(_.patch.isDefined))
      .getOrElse(throw ReviewError("UNKNOWN_TURN", s"review $id has no turn with a recorded start"))
    val to = toTurn.map(started)
    val fromManifest = from.manifest.get
    val (toEntries, toRepositories) = to match
      case Some(turn) => (turn.manifest.get.entries, turn.manifest.get.repositories)
      case None =>
        val observation = Observation.observe(git, root)
        (observation.entries, observation.repositories)
    val repositories = (fromManifest.repositories ++ toRepositories).toSet
    val files = Observation.changes(fromManifest.entries, toEntries)
    val nested = files.filter(repositories)
    val scratch = Files.createTempDirectory("ko-review-diff-")
    try
      val a = Files.createDirectory(scratch.resolve("a"))
      val b = Files.createDirectory(scratch.resolve("b"))
      val leftOut = Patches.rebuild(git, root, review.chain(from), files.toSet, a)
        .filter(fromManifest.entries.contains) ++ (to match
        case Some(turn) => Patches.rebuild(git, root, review.chain(turn), files.toSet, b).filter(toEntries.contains)
        case None =>
          val observation = Observation(None, collection.immutable.TreeMap.from(toEntries), toRepositories)
          files.foreach(path => Patches.copyCurrent(git, root, path, observation, b))
          Set.empty)
      leftOut.foreach(path => Seq(a, b).foreach(side => Files.deleteIfExists(side.resolve(path))))
      ctx.out.write(git.diffTrees(scratch, a, b, gitOptions))
      ctx.out.flush()
      val unknown = (leftOut.toSeq ++ nested).sorted
      if unknown.nonEmpty then
        ctx.err.println(
          "These paths changed, and the review keeps no copy of their content: " + unknown.mkString(", "))
    finally Patches.delete(scratch)
    None

  /** Rebuilds a turn's start in `directory`, without the paths that the patches leave out, which the output lists. */
  def restore(id: String, turnNumber: Int, directory: String): JsonObject =
    val root = worktreeRoot()
    val review = {
      existingReview(root, id)
      Review.load(store, root, id, lockedElsewhere = false)
    }
    current = Some((store, root, id))
    val turn = review.turns.find(turn => turn.number == turnNumber && turn.patch.isDefined)
      .getOrElse(throw ReviewError("UNKNOWN_TURN", s"review $id has no turn $turnNumber with a recorded start"))
    val target = ctx.resolve(directory)
    if Files.exists(target) && listDirectory(target).nonEmpty then
      throw ReviewError("DIRECTORY_NOT_EMPTY", s"$target is not empty: name a new or empty directory")
    Files.createDirectories(target)
    val chain = review.chain(turn)
    val manifest = turn.manifest.get
    val leftOut = Patches.rebuild(git, root, chain, Patches.paths(git, root, chain), target)
      .filter(manifest.entries.contains)
    JsonObject(
      "reviewId" -> id.asJson,
      "turn" -> turnNumber.asJson,
      "directory" -> target.toString.asJson,
      "leftOutPaths" -> (leftOut.toSeq ++ manifest.repositories).sorted.asJson,
    )

  def delete(id: String): JsonObject =
    val root = worktreeRoot()
    val dir = existingReview(root, id)
    withLock(dir, id): () =>
      Patches.delete(dir)
    JsonObject("reviewId" -> id.asJson, "removedDirectory" -> dir.toString.asJson)

  def defaults(reviewerName: String): JsonObject = Reviewer.named(reviewerName).get.defaults(ctx, worktreeRoot())

  def digest(): JsonObject =
    val root = worktreeRoot()
    val observation = Observation.observe(git, root)
    JsonObject(
      "worktree" -> root.toString.asJson,
      "head" -> observation.head.asJson,
      "contentDigest" -> observation.contentDigest.asJson,
      "files" -> observation.entries.size.asJson,
    )

  /** The JSON that a failure adds: the review it names and what it shows, when the command had opened one. */
  def failureContext(): JsonObject =
    current.filter((store, root, id) => Files.isDirectory(store.reviewDir(root, id))).map: (store, root, id) =>
      try
        val review = Review.load(store, root, id, lockedElsewhere = false)
        JsonObject(
          "reviewId" -> id.asJson,
          "status" -> review.status.asJson,
          "reviewPath" -> review.dir.toString.asJson,
          "inspect" -> inspectLines(review).asJson,
        )
      catch case _: ReviewError => JsonObject("reviewId" -> id.asJson)
    .getOrElse(JsonObject.empty)

  // The turn

  /** Runs one reviewer turn under the review's lock. Until a turn has been answered, the turn is the review request,
    * on the thread that an earlier failed turn opened, if there is one. */
  private def runTurn(
      root: Path,
      review: Review,
      reviewer: Reviewer,
      program: Path,
      model: Option[String],
      effort: Option[String],
      instructions: Option[String],
      message: String,
  ): JsonObject =
    if review.escalated then
      throw ReviewError("REVIEW_CLOSED", s"review ${review.id} is USER_DECISION_REQUIRED; start a new review")
    // A turn that ends in an error does not count, so retries after a usage limit do not use up the review.
    if review.limitReached then
      throw ReviewError("LOOP_LIMIT_REACHED",
        s"review ${review.id} reached ${review.start.maxAnsweredTurns} answered turns")
    val before = Observation.observe(git, root)
    val scope = Scopes(git, root).against(review.start.base.map(_.commit).orElse(before.head))
    val number = review.turns.lastOption.map(_.number).getOrElse(0).max(highestTurnDirectory(review.dir)) + 1
    val prompt = this.prompt(review, instructions, before, scope, message, number)
    val dir = Files.createDirectory(review.dir.resolve("turns").resolve(Turn.idOf(number)))
    val from = review.nextFrom(review.start.base.map(_.commit).orElse(before.head))
    write(dir.resolve("request.json"), RequestFile(
      FormatVersion, now(), reviewer.name, model, effort, Reviewer.version(ctx, program), ctx.pluginVersion,
      instructions, message, scope, Some(from), coordinator(),
    ))
    var exitStatus: Option[Int] = None
    def record(error: ReviewError): ReviewError =
      try write(dir.resolve("outcome.json"), OutcomeFile(FormatVersion, now(), exitStatus, error = Some(error.toJson)))
      catch case _: java.io.IOException => () // the error itself is still reported
      error
    val (result, after) =
      try
        write(dir.resolve("manifest.json"), ManifestFile(FormatVersion, now(), before.entries, before.repositories))
        val fromTurn = from.turn.flatMap(id => review.turns.find(_.id == id))
        Patches.write(
          git, root,
          fromTurn.map(review.chain).getOrElse(Chain(from.commit, Vector.empty)),
          fromTurn.flatMap(_.manifest).map(_.entries),
          before,
          dir.resolve("start.patch"),
        )
        val (status, result) = runReviewer(root, review, reviewer, program, model, effort, prompt, dir)
        exitStatus = Some(status)
        // A second observation: what the reviewer read must be what is still there.
        val after = Observation.observe(git, root)
        if after.contentDigest != before.contentDigest then
          throw ReviewError(
            "WORKTREE_CHANGED_DURING_REVIEW",
            s"the working files changed while ${reviewer.name} reviewed them; the result is discarded, review again",
            JsonObject("before" -> before.contentDigest.asJson, "after" -> after.contentDigest.asJson,
              "paths" -> Observation.changes(before.entries, after.entries).asJson),
          )
        (result, after)
      catch
        case ex: ReviewError => throw record(ex)
        case ex: Git.Failure => throw record(ReviewError.fromGit(ex))
        case ex: Git.UndecodablePath => throw record(ReviewError.fromPath(ex))
        case _: InterruptedException =>
          Thread.interrupted() // a file channel closes on a pending interrupt, and the outcome must still be written
          throw record(Interruption.error(reviewer))
        case ex: Exception => throw record(ReviewError("HELPER_FAILED", ex.toString))
    write(dir.resolve("outcome.json"), OutcomeFile(FormatVersion, now(), exitStatus, result = Some(result)))
    val summary = summaryOf(root, review.id, Some(after))
    summary
      .add("disposition", result.disposition.asJson)
      .add("summary", result.summary.asJson)
      .add("findings", Json.arr(result.findings.map(Encoders.finding(_))*))
      .add("suggestions", Json.arr(result.suggestions.map(Encoders.suggestion(_))*))
      .add("userDecision", result.userDecision.asJson)

  /** Runs the reviewer and returns its exit status and validated result. */
  private def runReviewer(
      root: Path,
      review: Review,
      reviewer: Reviewer,
      program: Path,
      model: Option[String],
      effort: Option[String],
      prompt: String,
      dir: Path,
  ): (Int, ReviewResult) =
    val resume = review.threadId
    val lastMessage = Files.createTempFile("ko-review-", ".last-message")
    try
      val schema = ctx.pluginRoot.resolve("schemas/review-result.schema.json")
      val command = reviewer.command(program, model, effort, resume, schema, lastMessage)
      val processes = ReviewerProcess(ctx.javaCommand)
      // Adoption covers the reviewer's run only, so the orphans adopted and killed are the reviewer's, not those of
      // the helper's own commands before and after the turn.
      Posix.setChildSubreaper(true)
      val streamed =
        try
          val leader = processes.startLeader()
          val process =
            try processes.startReviewer(leader, command, root, reviewer.environment(ctx.env, effort),
              dir.resolve("reviewer.stderr"))
            catch
              case ex: Exception =>
                Posix.killGroup(leader.pid(), Posix.SIGKILL)
                ReviewerProcess.reapUninterruptibly(leader)
                throw ex
          processes.stream(process, leader, prompt.getBytes(UTF_8), review.start.timeoutSeconds.toLong,
            dir.resolve("reviewer.stdout"), reviewer.threadId,
            id => if resume.isEmpty then write(dir.resolve("thread.json"), ThreadFile(FormatVersion, now(), id)))
        finally Posix.setChildSubreaper(false)
      val stderr = Files.readString(dir.resolve("reviewer.stderr"), UTF_8)
      val status = streamed.exitStatus
      if streamed.timedOut then
        throw reviewer.error("TURN_INTERRUPTED",
          s"${reviewer.name} exceeded ${review.start.timeoutSeconds} seconds and was killed")
      if status != 0 || streamed.events.exists(reviewer.failed) then
        throw Failures.classify(ctx, reviewer, status, stderr, streamed.events)
      streamed.badLine.foreach: line =>
        throw reviewer.error("INVALID_RESULT", s"${reviewer.name} printed a line that is not JSON",
          "line" -> line.asJson)
      if streamed.threadId.isEmpty then
        throw Failures.reviewerFailed(reviewer, s"${reviewer.name} ended without a ${reviewer.threadEvent} event",
          stderr, streamed.events, "stderr" -> stderr.takeRight(2000).asJson)
      if resume.isDefined && streamed.threadId != resume then
        throw reviewer.error("REVIEWER_RESUME_MISMATCH",
          s"${reviewer.name} resumed a different thread than this review's",
          "expected" -> resume.asJson, "actual" -> streamed.threadId.asJson)
      val text = reviewer.finalResult(streamed.events, lastMessage)
        .getOrElse(throw reviewer.error("INVALID_RESULT", s"${reviewer.name} wrote no final message"))
      val json = io.circe.parser.parse(text).fold(
        ex => throw reviewer.error("INVALID_RESULT", s"${reviewer.name}'s final message is not JSON: ${ex.message}"),
        identity,
      )
      ResultValidation.problem(json).foreach: problem =>
        throw reviewer.error("INVALID_RESULT", s"${reviewer.name}'s final message does not follow the schema: $problem",
          "result" -> json)
      (status, json.as[ReviewResult].fold(ex => throw reviewer.error("INVALID_RESULT", ex.getMessage), identity))
    finally Files.deleteIfExists(lastMessage): Unit

  private def prompt(review: Review, instructions: Option[String], before: Observation, scope: Seq[String],
      message: String, number: Int): String =
    val first = review.lastAnswered.isEmpty
    val text = StringBuilder(Files.readString(ctx.pluginRoot.resolve("prompts").resolve(
      if first then "reviewer.md" else "continue.md")))
    // The instructions go into every turn, so that they stay in force however long the thread grows.
    instructions.foreach: words =>
      text ++= "\n---\n\n# Instructions from the user\n\n"
      text ++= "These take precedence over the reviewer instructions above.\n\n"
      text ++= trimNewlines(words) + "\n"
    // The scope names a commit id, not HEAD, so a commit or checkout during the turn does not move what the reviewer
    // reads; the check after the turn compares only the files' content.
    val scopeText = (review.start.base, before.head) match
      case (Some(base), _) =>
        s"Review the changes since `${base.ref}`, commit ${base.commit}: `git diff ${base.commit}` shows them, " +
          "committed since then or not, plus untracked files."
      case (None, None) =>
        "The repository has no commit yet. Review every file in the working tree, untracked files included."
      case (None, Some(head)) =>
        s"Review the working tree's changes against commit $head, HEAD when this turn started: `git diff $head` plus " +
          "untracked files."
    text ++= "\n---\n\n# Scope\n\n" + scopeText + "\n"
    review.lastAnswered.foreach: last =>
      // The reviewer last read the tree in the turn it last answered, whatever failed since.
      val changed = Observation.changes(last.manifest.map(_.entries).getOrElse(Map.empty), before.entries)
      val readThen = last.request.scope.toSet
      val entered = scope.filter(path => !changed.contains(path) && !readThen(path))
      def quoted(paths: Seq[String]) = paths.map(path => s"`$path`").mkString(", ")
      val sentences = Seq(
        Some(
          if changed.nonEmpty then s"Since your answer in turn ${last.number}, the content of these paths changed: " +
            quoted(changed) + "."
          else s"No file's content changed since your answer in turn ${last.number}.",
        ),
        Option.when(entered.nonEmpty)("These paths entered the scope since then without a content change, as when " +
          "HEAD moves under a file: " + quoted(entered) + "."),
        Option.when(changed.nonEmpty || entered.nonEmpty)("Every other path is as you read it then."),
      ).flatten
      text ++= "\n---\n\n# Changes since your last turn\n\n" + sentences.mkString(" ") + "\n"
    // A failed turn may or may not have left the author's message in the reviewer's thread. The author writes the
    // next message as a sequel, so the next turn sends the unanswered messages again, as written, because the
    // reviewer reads code in them.
    for turn <- review.turns if review.lastAnswered.forall(_.number < turn.number) do
      text ++= s"\n---\n\n# The author's message of turn ${turn.number}, which you did not answer\n\n" +
        "Your turn on it ended in an error before you answered. The author's latest message follows the unanswered " +
        "ones.\n\n" + trimNewlines(turn.request.message) + "\n"
    val heading = if first then "# Review request from the author" else s"# The author's response, turn $number"
    text ++= "\n---\n\n" + heading + "\n\n" + trimNewlines(message) + "\n"
    text.result()

  // Helpers

  private def summaryOf(root: Path, id: String, observed: Option[Observation] = None): JsonObject =
    val dir = existingReview(root, id)
    val review = Review.load(store, root, id, ReviewLock.held(dir))
    current = Some((store, root, id))
    val observation = observed.getOrElse(Observation.observe(git, root))
    val freshness = Freshness.of(review, observation, Scopes(git, root))
    def reviewed(turn: Turn) = Json.obj(
      "turn" -> turn.number.asJson,
      "contentDigest" -> Observation.digestOf(turn.manifest.map(_.entries).getOrElse(Map.empty)).asJson,
      "at" -> turn.outcome.map(_.writtenAt).asJson,
    )
    JsonObject(
      "reviewId" -> id.asJson,
      "worktree" -> root.toString.asJson,
      "reviewer" -> review.reviewer.asJson,
      "model" -> review.model.asJson,
      "effort" -> review.effort.asJson,
      "status" -> review.status.asJson,
      "effectiveStatus" -> freshness.effectiveStatus.asJson,
      "turn" -> review.latest.map(_.number).getOrElse(0).asJson,
      "answeredTurns" -> review.answered.size.asJson,
      "maxAnsweredTurns" -> review.start.maxAnsweredTurns.asJson,
      "instructions" -> review.instructions.asJson,
      "base" -> review.start.base.asJson,
      "threadId" -> review.threadId.asJson,
      "lastReviewed" -> review.lastAnswered.map(reviewed).asJson,
      "approved" -> review.approved.map(reviewed).asJson,
      "approvalFresh" -> freshness.fresh.asJson,
      "staleReasons" -> freshness.staleReasons.asJson,
      "activity" -> activity(review).asJson,
      "currentHead" -> observation.head.asJson,
      "currentContentDigest" -> observation.contentDigest.asJson,
      "lastError" -> review.lastError.asJson,
      "createdAt" -> review.start.writtenAt.asJson,
      "updatedAt" -> review.updatedAt.asJson,
      "reviewPath" -> review.dir.toString.asJson,
      "inspect" -> inspectLines(review).asJson,
    )

  /** What a turn in progress shows: where the reviewer's output lands, and when the helper received its last event.
    * A recent event does not prove that the reviewer is still working. */
  private def activity(review: Review): Option[Json] =
    review.latest.filter(_ => review.inProgress).map: turn =>
      val stdout = turn.dir.resolve("reviewer.stdout")
      val last = Option.when(Files.exists(stdout)):
        String(Files.readAllBytes(stdout), UTF_8).split('\n').map(_.trim).filter(_.nonEmpty).lastOption
      .flatten.map: line =>
        val kind = io.circe.parser.parse(line).toOption.flatMap(_.asObject).flatMap(_("type")).flatMap(_.asString)
        Json.obj("type" -> kind.asJson, "receivedAt" -> timeText(Files.getLastModifiedTime(stdout).toInstant).asJson)
      val elapsed = parseTime(turn.request.writtenAt).map(started => Duration.between(started, Instant.now()).toSeconds)
      Json.obj(
        "turn" -> turn.number.asJson,
        "stdoutPath" -> stdout.toString.asJson,
        "startedAt" -> turn.request.writtenAt.asJson,
        "elapsedSeconds" -> elapsed.asJson,
        "lastEventReceived" -> last.asJson,
      )

  /** Commands that show the user how the review went. The skill relays them at the end. */
  private def inspectLines(review: Review): Seq[String] =
    val started = review.turns.filter(_.patch.isDefined)
    Seq(Some(s"ko-review transcript ${review.id}  # one section per turn"),
      Option.when(started.nonEmpty)(s"ko-review diff ${review.id}  # your tree against the approved turn's start"),
      Option.when(started.size >= 2)(s"ko-review diff ${review.id} --from ${started.head.number} --to " +
        s"${started.last.number}  # what changed during the review"),
      Some("ko-review list  # this worktree's reviews, by id"),
      Some(s"ko-review delete ${review.id}  # the review's files, once you no longer need them"),
    ).flatten

  /** The session that runs this command, from what its tool exports: Claude Code its session, its executable, whose
    * `--version` the helper asks, and its effort, which follows `/effort`; Codex its thread and version. A fact that
    * cannot be read is absent, and never stops the turn. */
  private def coordinator(): Option[Coordinator] =
    def variable(name: String) = ctx.env.get(name).filter(_.nonEmpty)
    // CLAUDE_CODE_EXECPATH is undocumented; only output that names Claude Code is taken as its version.
    def claudeVersion(program: String) =
      try Reviewer.version(ctx, Path.of(program)).filter(_.endsWith("(Claude Code)"))
      catch case _: java.io.IOException | _: java.nio.file.InvalidPathException => None
    variable("CLAUDE_CODE_SESSION_ID").map: session =>
      Coordinator("claude", Some(session), variable("CLAUDE_CODE_EXECPATH").flatMap(claudeVersion),
        variable("CLAUDE_EFFORT"))
    .orElse(variable("CODEX_THREAD_ID").map(thread => Coordinator("codex", Some(thread), variable("CODEX_VERSION"))))

  private def worktreeRoot(): Path =
    git.toplevel(ctx.cwd).getOrElse(throw ReviewError(
      "NOT_A_GIT_REPOSITORY",
      s"${ctx.cwd} is not a Git working tree, and a review compares the files with a commit. Make it one, then retry:" +
        "\n\ngit init\ngit commit --allow-empty -m \"Start of the review\"\n\nThe files stay uncommitted, so the " +
        "review covers them all; a .gitignore keeps build outputs and secrets out of it.",
    ))

  private def readMessage(file: String): String =
    val text =
      try Files.readString(ctx.resolve(file))
      catch case ex: java.io.IOException => throw ReviewError("MESSAGE_UNREADABLE", s"cannot read $file: $ex")
    if text.isBlank then throw ReviewError("MESSAGE_UNREADABLE", s"$file is empty")
    text

  private def resolveBase(root: Path, ref: String): Base =
    git.resolveCommit(root, ref).map(commit => Base(ref = ref, commit = commit))
      .getOrElse(throw ReviewError("BASE_UNKNOWN", s"$ref is not a commit in this repository"))

  /** Refuses a review of nothing: a reviewer turn on an empty scope yields an approval that looks like an approval of
    * the session's committed work, which only `--base` brings into scope. A dirty worktree whose edits restore the
    * base's content has an empty scope too. */
  private def checkScope(root: Path, base: Option[Base]): Unit =
    if git.untrackedPaths(root).isEmpty then
      base.map(_.commit).orElse(git.head(root)) match
        case None =>
          // Unborn HEAD: the index lists a staged file after its deletion from disk, so what counts is a listed file
          // that is still there.
          if !git.indexPaths(root).exists(path => Observation.entry(git, root.resolve(path)).isDefined) then
            throw ReviewError("NOTHING_TO_REVIEW", "the repository has no files, so nothing is in the review's scope")
        case Some(commit) =>
          if !git.differsFrom(root, commit) then
            throw ReviewError(
              "NOTHING_TO_REVIEW",
              s"the working tree equals ${base.map(_.ref).getOrElse("HEAD")}, so nothing is in the review's scope" +
                (if base.isEmpty then "; to review commits made since a branch or commit, pass `--base REF`" else ""),
            )

  private def preconditions(reviewer: Reviewer): Path =
    val program = ctx.find(reviewer.name)
      .getOrElse(throw reviewer.error("REVIEWER_FAILED", s"${reviewer.name} is not on PATH"))
    val (signedIn, status) = reviewer.signedIn(ctx, program)
    if !signedIn then
      throw reviewer.error("REVIEWER_AUTH_FAILED", s"${reviewer.name} is not signed in: ${reviewer.signInAdvice}",
        "loginStatus" -> status.asJson)
    // Outside the sandbox there is no ruleset. Inside it, the ruleset that the launcher exports must allow one of the
    // reviewer's hosts.
    ctx.env.get("KO_AGENT_SANDBOX_EGRESS_RULESET").filter(_.nonEmpty).foreach: ruleset =>
      if !reviewer.hosts.exists(host => ruleset.contains(s"allow https://$host/")) then
        throw reviewer.error(
          "REVIEWER_EGRESS_DENIED",
          s"the egress ruleset allows none of ${reviewer.hosts.mkString(", ")}: relaunch the session with " +
            "--egress-preset naming both agents' presets, such as --egress-preset=anthropic,openai, and retry",
          "profile" -> ruleset.linesIterator.nextOption().asJson,
        )
    program

  private def mutableReviewer(review: Review): Reviewer =
    review.newerFormat.foreach: (path, version) =>
      throw ReviewError(
        "REVIEW_FORMAT_NEWER",
        s"${review.dir.relativize(path)} follows format $version, and this helper writes $FormatVersion: update the " +
          "plugin to continue this review",
      )
    val name = review.reviewer.getOrElse(throw ReviewError("REVIEW_CLOSED",
      s"review ${review.id} has no turn; start a new review"))
    Reviewer.named(name).getOrElse(throw ReviewError(
      "REVIEWER_UNSUPPORTED",
      s"review ${review.id} is a $name review; this helper runs ${Reviewer.all.map(_.name).mkString(", ")}",
    ))

  private def existingReview(root: Path, id: String): Path =
    val dir = store.reviewDir(root, id)
    if id.isEmpty || id.contains('/') || id.startsWith(".") || !Files.isDirectory(dir) then
      throw ReviewError("UNKNOWN_REVIEW", s"no review $id for $root")
    dir

  private def withLock[T](dir: Path, id: String)(body: () => T): T =
    val lock = ReviewLock.tryTake(dir)
      .getOrElse(throw ReviewError("REVIEW_LOCKED", s"another command holds review $id; retry when it finishes"))
    try body()
    finally lock.close()

  private def highestTurnDirectory(dir: Path): Int =
    listDirectory(dir.resolve("turns")).flatMap(_.getFileName.toString.toIntOption).maxOption.getOrElse(0)

  private def trimNewlines(text: String): String = text.reverse.dropWhile(_ == '\n').reverse

  /** Deletes every review under the state root whose latest record is RetentionDays old or more, whichever worktree
    * it belongs to, so that the reviews of a removed linked worktree or a deleted main worktree expire too. Returns the
    * deleted ids, and for each review that it could not delete, the id and the error. A review that another command
    * holds stays, silently. */
  private def expire(): (Vector[String], Vector[Json]) =
    val limit = Instant.now().minus(Duration.ofDays(RetentionDays))
    val expired = Vector.newBuilder[String]
    val failures = Vector.newBuilder[Json]
    for worktree <- store.worktreeDirs do
      for dir <- listDirectory(worktree.resolve("reviews")) do
        val id = dir.getFileName.toString
        try
          ReviewLock.tryTake(dir).foreach: lock =>
            try
              if latestRecord(dir).exists(!_.isAfter(limit)) then
                Patches.delete(dir)
                expired += id
            finally lock.close()
        catch
          case ex: java.io.IOException =>
            failures += Json.obj("reviewId" -> id.asJson,
              "error" -> ReviewError("STATE_IO_FAILED", ex.toString).toJson.asJson)
      // A worktree's directory goes once it holds no review. A directory that is not empty refuses the deletion.
      try
        Files.deleteIfExists(worktree.resolve("reviews"))
        Files.deleteIfExists(worktree.resolve("worktree.json"))
        Files.deleteIfExists(worktree)
      catch case _: java.io.IOException => ()
    (expired.result(), failures.result())

  /** The time of a review's latest record, or for a review whose records cannot be read, the start minute in its id. */
  private def latestRecord(dir: Path): Option[Instant] =
    val times = scala.util.Using.resource(Files.walk(dir)): paths =>
      import scala.jdk.CollectionConverters.*
      paths.iterator().asScala.filter(_.getFileName.toString.endsWith(".json")).toVector
    .flatMap: path =>
      try io.circe.parser.parse(Files.readString(path)).toOption.flatMap(_.hcursor.get[String]("writtenAt").toOption)
        .flatMap(parseTime)
      catch case _: java.io.IOException => None
    times.maxOption.orElse:
      try Some(LocalDateTime.parse(dir.getFileName.toString.take(15), ReviewStore.IdMinute)
          .atZone(ZoneId.systemDefault()).toInstant)
      catch case _: java.time.format.DateTimeParseException => None

/** The JSON of a result's items as the coordinator reads them: an absent location is null. */
private object Encoders:
  val finding: io.circe.Encoder[Finding] = finding => Json.obj("id" -> finding.id.asJson,
    "severity" -> finding.severity.asJson, "location" -> finding.location.asJson,
    "description" -> finding.description.asJson, "evidence" -> finding.evidence.asJson)
  val suggestion: io.circe.Encoder[Suggestion] = suggestion => Json.obj("id" -> suggestion.id.asJson,
    "kind" -> suggestion.kind.asJson, "location" -> suggestion.location.asJson,
    "description" -> suggestion.description.asJson, "reason" -> suggestion.reason.asJson)

/** Classifies a reviewer's failure by its exit status, stderr and failure events. */
object Failures:

  /** The reviewer's own words on its failure, such as a usage limit and when it resets: the message of its last
    * failure event, else the last line of its stderr. */
  def said(reviewer: Reviewer, stderr: String, events: Seq[JsonObject]): Option[String] =
    events.reverseIterator.filter(reviewer.failed).flatMap(reviewer.failureText).map(_.strip).find(_.nonEmpty)
      .orElse(stderr.linesIterator.map(_.strip).filter(_.nonEmpty).toSeq.lastOption)

  def reviewerFailed(reviewer: Reviewer, summary: String, stderr: String, events: Seq[JsonObject],
      detail: (String, Json)*): ReviewError =
    val message = said(reviewer, stderr, events).fold(summary)(words => s"$summary: $words")
    reviewer.error("REVIEWER_FAILED", message, detail*)

  def classify(ctx: CommandContext, reviewer: Reviewer, status: Int, stderr: String, events: Seq[JsonObject])
      : ReviewError =
    val messages = events.filter(reviewer.failed).map(event => reviewer.failureText(event).asJson.noSpaces)
    val lowered = (stderr + "\n" + messages.mkString("\n")).toLowerCase
    val detail = Seq("exitStatus" -> status.asJson, "stderr" -> stderr.takeRight(2000).asJson,
      "events" -> messages.takeRight(5).asJson)
    // A process that a signal ended reports 128 plus the signal's number to the JVM.
    if status > 128 && status < 128 + 65 then
      reviewer.error("TURN_INTERRUPTED", s"${reviewer.name} ended by signal ${status - 128}", detail*)
    else if lowered.contains(reviewer.lostThread) then
      reviewer.error("REVIEWER_FAILED", s"${reviewer.name} no longer has this review's thread; start a new review",
        detail*)
    else if "not logged in|login required|unauthorized|401|refresh token|reauthenticate|/login".r
        .findFirstIn(lowered).isDefined then
      reviewer.error("REVIEWER_AUTH_FAILED", s"${reviewer.name} is not signed in: ${reviewer.signInAdvice}", detail*)
    else if "403|proxy|connect tunnel|tls|network|dns|connection refused|timed out".r.findFirstIn(lowered).nonEmpty
    then
      reviewer.error("REVIEWER_EGRESS_DENIED",
        s"${reviewer.name} could not reach its provider; the diagnostics show what the proxy answered",
        (detail :+ ("egressCheck" -> egressDiagnostics(ctx, reviewer).asJson))*)
    else reviewerFailed(reviewer, s"${reviewer.name} failed", stderr, events, detail*)

  private def egressDiagnostics(ctx: CommandContext, reviewer: Reviewer): Option[Seq[String]] =
    ctx.find("ko-sandbox-egress-check").map: checker =>
      reviewer.hosts.flatMap: host =>
        Reviewer.output(ctx, Seq(checker.toString, host)).toSeq.flatMap((_, out, err) => (out + err).linesIterator)

/** The signal that ended the helper, which the main thread's interrupt stands for. */
object Interruption:
  @volatile var signal: Option[String] = None

  def error(reviewer: Reviewer): ReviewError = signal match
    case Some(name) => ReviewError("TURN_INTERRUPTED", s"terminated by SIG$name")
    case None => reviewer.error("TURN_INTERRUPTED", s"interrupted while ${reviewer.name} ran")
