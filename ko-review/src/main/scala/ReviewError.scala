package koreview

import io.circe.{Json, JsonObject}
import io.circe.syntax.*

/** A failure that a command reports as `{"error": {"code": …, "message": …, …}}`. */
final class ReviewError(val code: String, val message: String, val detail: JsonObject = JsonObject.empty)
    extends Exception(message):
  def toJson: JsonObject = JsonObject("code" -> code.asJson, "message" -> message.asJson).deepMerge(detail)

object ReviewError:
  /** A failure of the reviewer, not of the helper. The error names the reviewer, so that the skill's advice fits. */
  def ofReviewer(reviewer: String, code: String, message: String, detail: (String, Json)*): ReviewError =
    ReviewError(code, message, JsonObject.fromIterable(("reviewer" -> reviewer.asJson) +: detail))

  def fromPath(failure: Git.UndecodablePath): ReviewError =
    ReviewError("PATH_NOT_UTF8", s"${failure.getMessage}: the helper cannot read the file, so it cannot tell whether " +
      "the file changed. Rename it, or add it to .gitignore")

  def fromGit(failure: Git.Failure): ReviewError =
    ReviewError("GIT_FAILED", failure.getMessage, JsonObject("stderr" -> failure.stderr.takeRight(2000).asJson))
