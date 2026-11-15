package koreview

import scala.util.matching.Regex

/** Renders a review's turns as Markdown, for the `transcript` command. */
object Transcript:

  /** The whole review: a header, one section per turn, and the commands that show more. */
  def review(review: Review, display: String, effectiveStatus: String, inspect: Seq[String]): String =
    val header = Seq(
      Some(s"# $display review ${review.id}"),
      Some(""),
      Some(s"- Worktree: ${review.worktree}"),
      Some(s"- Status: $effectiveStatus"),
      review.start.base.map(base => s"- Base: ${base.ref} (${base.commit})"),
      Some(s"- $display thread: ${review.threadId.getOrElse("none")}"),
      Some(s"- Started: ${review.start.writtenAt}"),
      Some(""),
    ).flatten
    val body = review.turns.flatMap(turn => Seq(s"## Turn ${turn.number}", "") ++ turnLines(review, display, turn))
    (header ++ body ++ Seq("## How to see how it went", "", "```sh") ++ inspect ++ Seq("```", "")).mkString("\n")

  /** One turn, headed by the review and the turn. */
  def turn(review: Review, display: String, turn: Turn): String =
    (Seq(s"# Review ${review.id}, turn ${turn.number}", "") ++ turnLines(review, display, turn)).mkString("\n") + "\n"

  private def turnLines(review: Review, display: String, turn: Turn): Seq[String] =
    val previous = review.turns.takeWhile(_.number < turn.number).lastOption
    val instructions = turn.request.instructions.filter: text =>
      !previous.exists(earlier => Review.sameInstructions(earlier.request.instructions, Some(text)))
    val user = instructions.toSeq.flatMap(text =>
      Seq("### Instructions from the user, from this turn on", "", shifted(text), ""))
    val through = turn.request.coordinator.map: coordinator =>
      ", through the coordinator: " + (Seq(Some(coordinator.tool), coordinator.version).flatten.mkString(" ") +:
        coordinator.effort.map(effort => s"$effort effort").toSeq).mkString(", ")
    val author = Seq("### The author" + through.getOrElse(""), "", shifted(turn.request.message), "")
    val outcome = turn.outcome.toSeq.flatMap: outcome =>
      outcome.result.map(resultLines(display, _)).getOrElse:
        val error = outcome.error.getOrElse(io.circe.JsonObject.empty)
        def field(key: String) = error(key).flatMap(_.asString).getOrElse("")
        Seq(s"### Error: ${field("code")}", "", field("message"), "")
    val escalation = turn.escalation.toSeq.flatMap: escalation =>
      Seq("### The coordinator agreed that the user must decide", "", shifted(escalation.message), "")
    user ++ author ++ outcome ++ escalation

  private def resultLines(display: String, result: ReviewFiles.ReviewResult): Seq[String] =
    def where(location: Option[String]) = location.map(text => s" `$text`").getOrElse("")
    val findings = result.findings.flatMap: finding =>
      Seq(s"- **${finding.id}** (${finding.severity})${where(finding.location)}: ${finding.description}",
        s"  Evidence: ${finding.evidence}")
    val suggestions = result.suggestions.flatMap: suggestion =>
      Seq(s"- **${suggestion.id}** (${suggestion.kind})${where(suggestion.location)}: ${suggestion.description}",
        s"  Reason: ${suggestion.reason}")
    val decision = result.userDecision.toSeq.flatMap: decision =>
      Seq(s"- Issue: ${decision.issue}", s"- $display's position: ${decision.reviewerPosition}",
        s"- Why evidence cannot decide: ${decision.whyTechnicalEvidenceCannotDecide}",
        s"- Decision requested: ${decision.decisionRequested}", "")
    Seq(s"### $display: ${result.disposition}", "", result.summary, "") ++
      (if findings.isEmpty then Nil else findings :+ "") ++
      (if suggestions.isEmpty then Nil
       else Seq("Suggestions, which do not block approval:", "") ++ suggestions :+ "") ++
      decision

  // A fence after any list and block quote markers, which group 1 holds, and any indentation.
  private val FenceOpening = """((?:[ \t]*(?:[-+*]|\d{1,9}[.)])[ \t]+|[ \t]*>[ \t]?)*)[ \t]*(`{3,}|~{3,}).*""".r
  private val ListMarker = """[-+*]|\d{1,9}[.)]""".r
  private val AtxHeading = """( {0,3})(#{1,6})(?=[ \t]|$)""".r

  /** Shifts the message's ATX headings two levels down, at most to level 6, under the `###` heading that names who
    * wrote the message.
    *
    * A line that may be code stays as written, so a misreading can leave a heading unshifted but never change code.
    * Any line that could open a fence opens one, and only a line that certainly closes the fence closes it. Such a
    * closing line repeats the opening line's containers, with their list markers as spaces. After the containers, the
    * closing line has at most three spaces, a run of the fence's character at least as long, and nothing else.
    */
  def shifted(markdown: String): String =
    var fence: Option[(String, Char, Int)] = None // containers a closing line repeats, the character, the length
    markdown.reverse.dropWhile(_ == '\n').reverse.linesIterator.map: line =>
      fence match
        case None =>
          line match
            case FenceOpening(prefix, run) =>
              val containers =
                ListMarker.replaceAllIn(Option(prefix).getOrElse(""), marker => " " * marker.matched.length)
              fence = Some((containers, run.head, run.length))
              line
            case _ =>
              AtxHeading.findPrefixMatchOf(line) match
                case Some(heading) =>
                  heading.group(1) + "#" * math.min(heading.group(2).length + 2, 6) + line.substring(heading.end)
                case None => line
        case Some((containers, character, length)) =>
          val closing = (" {0,3}(" + Regex.quote(character.toString) + "{" + length + ",})[ \\t]*").r
          if line.startsWith(containers) && closing.matches(line.substring(containers.length)) then fence = None
          line
    .mkString("\n")
