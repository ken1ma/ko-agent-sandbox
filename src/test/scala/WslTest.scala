// Tests how Wsl reads WSL's version out of what `wsl --version` answers, in either encoding and any language.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets

import HostCommands.Run
import Wsl.versionOf

class WslTest extends munit.FunSuite:

  private def answer(firstLine: String, utf16: Boolean = false, exit: Int = 0) =
    val text = s"$firstLine\r\nカーネル バージョン: 6.18.58.1-1\r\nWSLg バージョン: 1.0.79\r\n"
    val charset = if utf16 then StandardCharsets.UTF_16LE else StandardCharsets.UTF_8
    Right(Run(exit, text.getBytes(charset), ""))

  test("the version is the first line's, from the English or the localized answer, in UTF-8 or UTF-16LE"):
    for
      utf16 <- Seq(false, true)
      (line, version) <- Seq("WSL バージョン: 3.0.5.0" -> "3.0.5.0", "WSL version: 2.6.1.0" -> "2.6.1.0")
    do assertEquals(versionOf(answer(line, utf16)), Right(version), s"$line, UTF-16LE: $utf16")

  test("an answer that fails or names no version first says why"):
    assertEquals(versionOf(Left("wsl.exe is not on PATH")), Left("wsl.exe is not on PATH"))
    assertEquals(
      versionOf(answer("Invalid command line argument: --version", utf16 = true, exit = 1)),
      Left("`wsl --version` exited with 1: Invalid command line argument: --version"),
    )
    assertEquals(
      versionOf(Right(Run(1, Array.emptyByteArray, "E\u0000r\u0000r\u0000"))),
      Left("`wsl --version` exited with 1: Err"),
    )
    assertEquals(versionOf(Right(Run(1, Array.emptyByteArray, ""))), Left("`wsl --version` exited with 1"))
    assertEquals(
      versionOf(answer("Usage: wsl.exe [Argument]")),
      Left("`wsl --version` named no version first: Usage: wsl.exe [Argument]"),
    )
    assertEquals(
      versionOf(Right(Run(0, Array.emptyByteArray, ""))),
      Left("`wsl --version` named no version first: no output"),
    )
