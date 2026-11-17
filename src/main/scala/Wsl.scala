// Asks the Windows host's WSL what it is. The file depends on the launcher only for running and resolving host
// commands (HostCommands), so that it can move into a library.

package agentsandbox.launcher

import java.io.IOException
import java.nio.charset.StandardCharsets

import HostCommands.{findOnPath, Os, Run, runWithEnvironment}

object Wsl:

  /** The update that brings WSL and its kernel forward. */
  val UpdateCommands = "`wsl --update`, then `wsl --shutdown`"

  /** WSL's version, such as `3.0.5.0`, or why `wsl --version` did not give one. */
  def version(): Either[String, String] = versionOf(versionAnswer())

  /** What `wsl --version` answered, or why it gave no answer. */
  private def versionAnswer(): Either[String, Run] =
    findOnPath("wsl", Os.Windows).toRight("wsl.exe is not on PATH").flatMap: wsl =>
      try Right(runWithEnvironment(Map("WSL_UTF8" -> "1"), wsl.toString, "--version"))
      catch case ex: IOException => Left(s"$wsl did not start: ${ex.getMessage}")

  /**
   * The version that a `wsl --version` answer names, or why it names none.
   * - wsl.exe writes UTF-16LE without a BOM to a pipe (https://github.com/microsoft/WSL/issues/4607), and UTF-8 under
   *   WSL_UTF8=1. The probe sets the variable, because HostCommands reads stderr as UTF-8 and a localized error
   *   would arrive garbled. The decoding still tells the two apart by a NUL byte, for a wsl.exe that ignores it.
   * - The first line names WSL's own version in the English and Japanese answers: `WSL version: 3.0.5.0`,
   *   `WSL バージョン: 3.0.5.0`.
   */
  def versionOf(answer: Either[String, Run]): Either[String, String] =
    answer.flatMap: answered =>
      val charset = if answered.out.contains(0: Byte) then StandardCharsets.UTF_16LE else StandardCharsets.UTF_8
      val lines = String(answered.out, charset).linesIterator.map(_.trim).filter(_.nonEmpty).toVector
      if !answered.ok then
        val said = (lines ++ answered.err.replace("\u0000", "").linesIterator.map(_.trim).filter(_.nonEmpty))
          .headOption.fold("")(": " + _)
        Left(s"`wsl --version` exited with ${answered.exit}$said")
      else
        lines.headOption.flatMap(DottedVersion.findFirstIn)
          .toRight(s"`wsl --version` named no version first: ${lines.headOption.getOrElse("no output")}")

  private val DottedVersion = raw"\d+(?:\.\d+)+".r
