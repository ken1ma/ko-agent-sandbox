// Tests how the launcher finds, announces and drives podman: the `using:` line and its version warning, the one
// version probe, and the arguments that the launcher passes to podman.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.*
import FileHelper.*
import Podman.*

class PodmanTest extends munit.FunSuite:

  private val isWindows = scala.util.Properties.isWin

  test("the Podman announcement includes the client version without depending on a running service"):
    val noHome: String => Option[String] = _ => None
    for
      (path, os) <- Seq("/opt/podman/bin/podman" -> Os.Mac, "C:\\Podman\\podman.exe" -> Os.Windows)
      version <- Seq("6.1.1", "6.2.0-dev", "6.1.1+vendor.1")
    do
      val result = Run(0, s"podman version $version\r\n".getBytes, "")
      assertEquals(
        podmanUsingLine(path, Some(result), os = os, environment = noHome, color = false),
        s"using: $path ($version)",
      )

    val path = "/usr/bin/podman"
    for result <- Seq(
        None,
        Some(Run(127, "podman version 6.1.1".getBytes, "cannot execute")),
        Some(Run(0, Array.emptyByteArray, "")),
        Some(Run(0, "unexpected output\nsecond line".getBytes, "")),
      )
    do assertEquals(podmanUsingLine(path, result, os = Os.Linux, environment = noHome, color = false), s"using: $path")

  test("a podman older than README.md's prerequisite gets a warning, and an unparsed answer none"):
    def warning(answer: String, exit: Int = 0) = podmanUpgradeWarning(Some(Run(exit, answer.getBytes, "")))
    for version <- Seq("6.2.0", "6.2.0-dev", "6.2.1+vendor.1", "6.10.0", "7.0.0") do
      assertEquals(warning(s"podman version $version\r\n"), None, version)
    assertEquals(
      warning("podman version 6.1.4"),
      Some("podman 6.1.4 is older than 6.2.0; upgrade it"),
    )
    assert(warning("podman version 5.99.99").isDefined)
    assertEquals(warning("podman version 6.1.4", exit = 127), None)
    assertEquals(warning("unexpected output"), None)
    assertEquals(podmanUpgradeWarning(None), None)

  test("the Podman announcement shows the path as the log dir line does, with the directory grayed"):
    val (gray, off) = ("\u001b[38;5;245m", "\u001b[0m")
    val home: String => Option[String] = Map("HOME" -> "/Users/me").get
    assertEquals(
      podmanUsingLine("/Users/me/homebrew/bin/podman", None, os = Os.Mac, environment = home, color = true),
      s"using: $gray~/homebrew/bin/${off}podman",
    )
    assertEquals(
      podmanUsingLine("C:\\Program Files\\Podman\\podman.exe", None, os = Os.Windows, color = true),
      s"using: $gray\"C:\\Program Files\\Podman\\${off}podman.exe\"",
    )

  test("the announcement, the availability check and the machine record share one version probe"):
    assume(!isWindows, "the fake executable is a POSIX shell script")
    val directory = Files.createTempDirectory("podman-version").toRealPath()
    val executable = directory.resolve("podman")
    val calls = directory.resolve("podman.calls")
    def location(of: Class[?]) = Paths.get(of.getProtectionDomain.getCodeSource.getLocation.toURI).toString
    val classpath = Vector(
      PodmanResolutionProbe.getClass, Podman.getClass, HostCommands.getClass, scala.runtime.LazyVals.getClass,
      classOf[Option[?]],
    ).map(location).distinct.mkString(java.io.File.pathSeparator)
    val jvm = Paths.get(sys.props("java.home"), "bin", "java").toString
    try
      for
        status <- Seq(0, 1)
        kernel <- Seq(None, Some("podman machine kernel 7.2.5-200.fc44.aarch64"))
      do
        Files.writeString(
          executable,
          "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\nprintf 'podman version 6.1.1\\n'\n" +
            s"exit $status\n",
        )
        executable.toFile.setExecutable(true)
        val builder = ProcessBuilder(
          (Vector(jvm, "-cp", classpath, "agentsandbox.launcher.PodmanResolutionProbe") ++ kernel)*,
        )
        builder.environment().put("PATH", directory.toString)
        val process = builder.start()
        process.getOutputStream.close()
        val output = String(process.getInputStream.readAllBytes())
        val error = String(process.getErrorStream.readAllBytes())
        assertEquals(process.waitFor(), 0, error)
        val version = if status == 0 then "podman version 6.1.1" else "podman version unknown"
        assertEquals(
          output.linesIterator.toVector,
          Vector(s"${status == 0}", version, executable.toString, s"${status == 0}", version),
        )
        val suffix = if status == 0 then " (6.1.1)" else ""
        val tail = kernel.fold("")(", " + _)
        assertEquals(
          error.linesIterator.filter(_.startsWith("using:")).toVector,
          Vector(s"using: $executable$suffix$tail"),
        )
        assertEquals(Files.readString(calls), "--version\n")
        Files.delete(calls)
    finally deleteRecursively(directory)

  test("a quote-free script keeps its quotes, its newlines, its arguments and the caller's stdin"):
    assume(!isWindows, "runs the receiving shell, which a POSIX host has")
    // The clipboard's response writer reads the exec's stdin, so the script must not arrive on stdin.
    val script = """printf '%s|%s|' "$1" "$2"
                   |for word in *; do :; done
                   |cat""".stripMargin
    val words = quoteFreeSh(script, "my app/*", "it's \"quoted\"")
    // The first five words are the wrapper's own. The arguments after them are the caller's.
    assert(words.take(5).forall(word => !word.contains('"') && !word.contains('\n')), words)
    val process = ProcessBuilder(words*).redirectErrorStream(true).start()
    process.getOutputStream.write("from stdin".getBytes)
    process.getOutputStream.close()
    val output = String(process.getInputStream.readAllBytes())
    assertEquals(process.waitFor(), 0, output)
    assertEquals(output, "my app/*|it's \"quoted\"|from stdin")
    // The clipboard scripts take no argument, and a Windows launcher passes them the same way.
    for clipboard <- Seq(ClipboardRelay.sandboxRequestReader(), ClipboardRelay.sandboxResponseWriter()) do
      assert(quoteFreeSh(clipboard).forall(word => !word.contains('"') && !word.contains('\n')))

  test("a file bind is relabeled privately on an SELinux-enforcing host only"):
    val source = java.nio.file.Path.of("/state/leaf.key")
    assertEquals(
      fileBind(source, "/etc/leaf.key", "ro", selinuxEnforcing = false),
      s"--volume=$source:/etc/leaf.key:ro",
    )
    assertEquals(
      fileBind(source, "/etc/leaf.key", "rw", selinuxEnforcing = true),
      s"--volume=$source:/etc/leaf.key:rw,Z",
    )

object PodmanResolutionProbe:
  /** An argument is announced as the kernel before the first use of `podman`, as requirePodman announces it. The
    * later announcePodman call must print nothing. */
  def main(args: Array[String]): Unit =
    println(podmanRuns)
    println(podmanVersion())
    args.headOption.foreach(kernel => announcePodman(Some(kernel)))
    println(podman)
    announcePodman(None)
    println(podmanRuns)
    println(podmanVersion())
