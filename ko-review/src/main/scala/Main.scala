package koreview

import io.circe.{Json, JsonObject, Printer}
import io.circe.syntax.*
import java.nio.file.Path
import scala.util.control.NonFatal

/** Runs one stateful review cycle for its coordinator. ko-review/doc/design.md describes the design and the
  * commands' output. */
object Main:

  val Usage: String =
    """usage: ko-review [--repository DIR] COMMAND ...
      |
      |  start REVIEWER --message-file FILE [--instructions-file FILE] [--base REF] [--model NAME] [--effort LEVEL]
      |        [--max-answered-turns N] [--timeout SECONDS]
      |                          review the working tree on a new reviewer thread (REVIEWER: codex or claude), after
      |                          deleting the reviews not updated for 30 days
      |  continue REVIEW_ID --message-file FILE [--instructions-file FILE]
      |                          send the author's response to the review's thread; new instructions replace the earlier
      |  escalate REVIEW_ID --message-file FILE
      |                          record the coordinator's agreement that the user must decide
      |  check-approval REVIEW_ID succeed only if the approval covers the current working tree
      |  show REVIEW_ID          print the review's state
      |  list                    list this worktree's reviews, one short entry each
      |  approvals [--base REF] [--instructions-file FILE]
      |                          list the approved reviews whose approval covers part of the current scope
      |  transcript REVIEW_ID [--turn N]
      |                          print the review's transcript as Markdown
      |  diff REVIEW_ID [--from N] [--to M] [-- GIT_DIFF_OPTIONS]
      |                          git diff between turns' starts, or a turn's start and the working tree
      |  restore REVIEW_ID --turn N DIR
      |                          rebuild a turn's start in DIR
      |  delete REVIEW_ID        delete the review's files
      |  defaults REVIEWER       print the model and effort the reviewer would use, and the models it offers
      |  digest                  print the content digest of the reviewable files
      |""".stripMargin

  def main(arguments: Array[String]): Unit =
    val mainThread = Thread.currentThread()
    // The first terminating signal interrupts the command, which kills the reviewer, records the turn's error and
    // exits; later signals are ignored meanwhile.
    for name <- Seq("TERM", "HUP", "INT") do
      sun.misc.Signal.handle(sun.misc.Signal(name), _ =>
        if Interruption.signal.isEmpty then
          Interruption.signal = Some(name)
          mainThread.interrupt()
      )
    val javaCommand = Seq(
      Path.of(System.getProperty("java.home"), "bin", "java").toString,
      "--enable-native-access=ALL-UNNAMED",
      "--sun-misc-unsafe-memory-access=allow",
      "-cp",
      System.getProperty("java.class.path"),
    )
    val ctx = CommandContext(
      cwd = Path.of("").toAbsolutePath,
      env = sys.env,
      out = System.out,
      err = System.err,
      pluginRoot = Path.of(System.getProperty("ko-review.plugin-root", "")).toAbsolutePath, // set by bin/ko-review
      pluginVersion = Option(classOf[Commands].getPackage.getImplementationVersion),
      javaCommand = javaCommand,
    )
    System.exit(run(ctx, arguments.toSeq))

  private val Output = Printer.spaces2.copy(colonLeft = "")

  /** Runs the command that `arguments` name and returns the exit status: 0, 1 when the printed object holds an
    * `error`, and 2 for a usage error. */
  def run(ctx: CommandContext, arguments: Seq[String]): Int =
    val (options, command) = arguments match
      case "--repository" +: directory +: rest => (Some(directory), rest)
      case rest => (None, rest)
    val context = options.fold(ctx)(directory => ctx.copy(cwd = ctx.cwd.resolve(directory)))
    val commands = Commands(context)
    if command == Seq("--help") then
      context.out.print(Usage)
      return 0
    val result =
      try parse(commands, command).map(Right(_))
      catch
        case ex: ReviewError => Some(Left(ex))
        case ex: Git.Failure => Some(Left(ReviewError.fromGit(ex)))
        case ex: Git.UndecodablePath => Some(Left(ReviewError.fromPath(ex)))
        case _: InterruptedException =>
          Thread.interrupted()
          Some(Left(ReviewError("TURN_INTERRUPTED", s"terminated by SIG${Interruption.signal.getOrElse("INT")}")))
        case NonFatal(ex) => Some(Left(ReviewError("HELPER_FAILED", ex.toString)))
    result match
      case None =>
        context.err.print(Usage)
        2
      case Some(Right(output)) =>
        output.foreach(json => context.out.println(Output.print(Json.fromJsonObject(json))))
        context.out.flush()
        0
      case Some(Left(error)) =>
        val failureContext =
          try commands.failureContext()
          catch case NonFatal(_) => JsonObject.empty // reporting the original error must not fail on its context
        val json = JsonObject("error" -> error.toJson.asJson).deepMerge(failureContext)
        context.out.println(Output.print(Json.fromJsonObject(json)))
        context.out.flush()
        1

  /** Runs the command, or answers None for a usage error. */
  private def parse(commands: Commands, arguments: Seq[String]): Option[Option[JsonObject]] =
    def options(rest: Seq[String], names: Set[String]): Option[(Map[String, String], Seq[String])] =
      rest match
        case Seq() => Some(Map.empty -> Nil)
        case name +: value +: tail if names(name) =>
          options(tail, names).map((found, positional) => (found + (name -> value), positional))
        case name +: _ if name.startsWith("--") => None
        case value +: tail => options(tail, names).map((found, positional) => (found, value +: positional))
    def int(value: Option[String]): Option[Option[Int]] = value match
      case None => Some(None)
      case Some(text) => text.toIntOption.map(Some(_))
    def reviewer(name: String) = Reviewer.named(name).map(_.name)
    arguments match
      case "start" +: rest =>
        for
          (found, positional) <- options(rest, Set("--message-file", "--instructions-file", "--base", "--model",
            "--effort", "--max-answered-turns", "--timeout"))
          name <- positional match
            case Seq(name) => reviewer(name)
            case _ => None
          message <- found.get("--message-file")
          maximum <- int(found.get("--max-answered-turns"))
          timeout <- int(found.get("--timeout"))
        yield Some(commands.start(name, message, found.get("--instructions-file"), found.get("--base"),
          found.get("--model"), found.get("--effort"), maximum.getOrElse(12), timeout.getOrElse(3600)))
      case "continue" +: rest =>
        for
          case (found, Seq(id)) <- options(rest, Set("--message-file", "--instructions-file"))
          message <- found.get("--message-file")
        yield Some(commands.continueReview(id, message, found.get("--instructions-file")))
      case "escalate" +: rest =>
        for
          case (found, Seq(id)) <- options(rest, Set("--message-file"))
          message <- found.get("--message-file")
        yield Some(commands.escalate(id, message))
      case Seq("check-approval", id) => Some(Some(commands.checkApproval(id)))
      case Seq("show", id) => Some(Some(commands.show(id)))
      case Seq("list") => Some(Some(commands.list()))
      case "approvals" +: rest =>
        for case (found, Seq()) <- options(rest, Set("--base", "--instructions-file"))
        yield Some(commands.approvals(found.get("--base"), found.get("--instructions-file")))
      case "transcript" +: rest =>
        for
          case (found, Seq(id)) <- options(rest, Set("--turn"))
          turn <- int(found.get("--turn"))
        yield commands.transcript(id, turn)
      case "diff" +: rest =>
        val (own, gitOptions) = rest.span(_ != "--")
        for
          case (found, Seq(id)) <- options(own, Set("--from", "--to"))
          from <- int(found.get("--from"))
          to <- int(found.get("--to"))
        yield commands.diff(id, from, to, gitOptions.drop(1))
      case "restore" +: rest =>
        for
          case (found, Seq(id, directory)) <- options(rest, Set("--turn"))
          turn <- found.get("--turn").flatMap(_.toIntOption)
        yield Some(commands.restore(id, turn, directory))
      case Seq("delete", id) => Some(Some(commands.delete(id)))
      case Seq("defaults", name) => reviewer(name).map(name => Some(commands.defaults(name)))
      case Seq("digest") => Some(Some(commands.digest()))
      case _ => None
