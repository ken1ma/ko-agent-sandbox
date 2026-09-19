// Host command tests cover executable resolution, generated script paths and launcher diagnostics.
// FileHelperTest and DirectoryStreamsTest cover the shared file operations.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.*
import FileHelper.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  test("POSIX log paths abbreviate only the host user's home"):
    assume(!isWindows, "POSIX path spellings need a POSIX filesystem")
    val root = Paths.get("").toAbsolutePath.getRoot
    val home = root.resolve("Users").resolve("test user")
    val otherHome = root.resolve("Users").resolve("someone else")
    for os <- Seq(Os.Linux, Os.Mac) do
      val environment = Map("HOME" -> home.toString, "USERPROFILE" -> otherHome.toString)
      for name <- Seq("proxy-run.log", "run-on-host-run.log") do
        val relative = Paths.get("logs", name)
        val log = home.resolve(relative)
        assertEquals(displayPath(log, os, environment.get), s"~${root.getFileSystem.getSeparator}$relative")
      assertEquals(displayPath(home, os, environment.get), "~")
      for (outside, expected) <- Seq(
          otherHome.resolve("log") -> s"'${otherHome.resolve("log")}'",
          home.resolveSibling("test user-other").resolve("log") ->
            s"'${home.resolveSibling("test user-other").resolve("log")}'",
          root.resolve("logs").resolve("proxy-run.log") -> root.resolve("logs").resolve("proxy-run.log").toString,
          Paths.get("logs", "proxy-run.log") -> "logs/proxy-run.log",
        )
      do assertEquals(displayPath(outside, os, environment.get), expected)
      for missing <- Seq(None, Some(""), Some("relative/home"), Some("bad\u0000home")) do
        val log = home.resolve("log")
        assertEquals(displayPath(log, os, _ => missing), s"'$log'")

  test("POSIX log paths paste into a shell as one unchanged argument, including after home expansion"):
    assume(!isWindows, "the round trip uses a POSIX shell")
    val home = Paths.get("/Users/test user")
    val environment = Map("HOME" -> home.toString)
    for
      os <- Seq(Os.Linux, Os.Mac)
      directory <- Seq(home, Paths.get("/var/log"))
      name <- Seq("proxy-run.log", "host command.log", "quote's\"$cash$(printf changed);[glob]*\\backslash.log")
    do
      val path = directory.resolve(name)
      val displayed = displayPath(path, os, environment.get)
      for label <- Seq("egress log", "host command log", "egress log dir", "egress tls ca") do
        assertEquals(pathLine(label, path, os, environment.get), s"$label: $displayed")
      assertEquals(pathLine("==>", path, os, environment.get, separator = " "), s"==> $displayed")
      val builder = ProcessBuilder("/bin/sh", "-c", s"set -- $displayed; printf '%s\\n' \"$$#\"; printf '%s' \"$$1\"")
      builder.environment().put("HOME", home.toString)
      val process = builder.start()
      process.getOutputStream.close()
      val output = String(process.getInputStream.readAllBytes())
      val error = String(process.getErrorStream.readAllBytes())
      assertEquals(process.waitFor(), 0, error)
      assertEquals(output, s"1\n$path", displayed)
    assertEquals(displayPath(home.resolve("host command.log"), Os.Mac, environment.get), "~/'host command.log'")
    val posix = Paths.get("/var/log/$USER.log")
    assertEquals(pathLine("egress log", posix, Os.Linux, _ => None), "egress log: '/var/log/$USER.log'")

  test("Windows log paths quote spaces and separators for cmd.exe and PowerShell"):
    for
      user <- Seq("kenichi", "test user", "test&user", "test(user)", "test^user", "test;user", "test'user")
      name <- Seq("proxy-run.log", "run-on-host-run.log")
    do
      val home = s"C:\\Users\\$user"
      val path = Paths.get(s"$home\\AppData\\Local\\ko-agent-sandbox\\log\\$name")
      val expected = if user == "kenichi" then path.toString else s"\"$path\""
      assertEquals(displayPath(path, Os.Windows, _ => Some(home)), expected)
      for label <- Seq("egress log", "host command log", "egress log dir", "egress tls ca") do
        assertEquals(pathLine(label, path, Os.Windows, _ => Some(home)), s"$label: $expected")
      assertEquals(pathLine("==>", path, Os.Windows, separator = " "), s"==> $expected")

  test("Windows paths with expansions use labeled PowerShell literals, including embedded quote characters"):
    for
      (name, escaped) <- Seq(
        "$USER.log" -> "$USER.log",
        "$(Write-Output changed).log" -> "$(Write-Output changed).log",
        "%USERPROFILE%.log" -> "%USERPROFILE%.log",
        "!USERNAME!.log" -> "!USERNAME!.log",
        "back`tick.log" -> "back`tick.log",
        "a'$USER.log" -> "a''$USER.log",
        "\u2018\u2019\u201a\u201b$USER.log" -> "\u2018\u2018\u2019\u2019\u201a\u201a\u201b\u201b$USER.log",
        "\u201c\u201d\u201e.log" -> "\u201c\u201d\u201e.log",
      )
      label <- Seq("egress log", "host command log", "egress log dir", "egress tls ca")
    do
      val path = Paths.get(s"C:\\logs\\$name")
      val expected = s"'C:\\logs\\$escaped'"
      assertEquals(displayPath(path, Os.Windows), expected)
      assertEquals(pathLine(label, path, Os.Windows), s"$label (PowerShell): $expected")
      assertEquals(pathLine("==>", path, Os.Windows, separator = " "), s"==> (PowerShell) $expected")

  test("the Podman announcement includes the client version without depending on a running service"):
    for
      path <- Seq("/opt/podman/bin/podman", "C:\\Program Files\\Podman\\podman.exe")
      version <- Seq("6.1.1", "6.2.0-dev", "6.1.1+vendor.1")
    do
      val result = Run(0, s"podman version $version\r\n".getBytes, "")
      assertEquals(podmanUsingLine(path, Some(result)), s"using: $path (v$version)")

    val path = "/usr/bin/podman"
    for result <- Seq(
        None,
        Some(Run(127, "podman version 6.1.1".getBytes, "cannot execute")),
        Some(Run(0, Array.emptyByteArray, "")),
        Some(Run(0, "unexpected output\nsecond line".getBytes, "")),
      )
    do assertEquals(podmanUsingLine(path, result), s"using: $path")

  test("the Podman announcement, availability check, and machine record share one version probe"):
    assume(!isWindows, "the fake executable is a POSIX shell script")
    val directory = Files.createTempDirectory("podman-version").toRealPath()
    val executable = directory.resolve("podman")
    val calls = directory.resolve("podman.calls")
    def location(of: Class[?]) = Paths.get(of.getProtectionDomain.getCodeSource.getLocation.toURI).toString
    val classpath = Vector(
      PodmanResolutionProbe.getClass, HostCommands.getClass, scala.runtime.LazyVals.getClass, classOf[Option[?]],
    ).map(location).distinct.mkString(java.io.File.pathSeparator)
    val jvm = Paths.get(sys.props("java.home"), "bin", "java").toString
    try
      for status <- Seq(0, 1) do
        Files.writeString(
          executable,
          "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.calls\"\nprintf 'podman version 6.1.1\\n'\n" +
            s"exit $status\n",
        )
        executable.toFile.setExecutable(true)
        val builder = ProcessBuilder(jvm, "-cp", classpath, "agentsandbox.launcher.PodmanResolutionProbe")
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
        val suffix = if status == 0 then " (v6.1.1)" else ""
        assertEquals(error.linesIterator.filter(_.startsWith("using:")).toVector, Vector(s"using: $executable$suffix"))
        assertEquals(Files.readString(calls), "--version\n")
        Files.delete(calls)
    finally deleteRecursively(directory)

  test("only an explicit yes is consent"):
    assert(consented(Some("y")))
    assert(consented(Some("Y")))
    assert(consented(Some(" YES ")))
    assert(!consented(Some("")))
    assert(!consented(Some("n")))
    assert(!consented(Some("yeah")))
    assert(!consented(None))

  test("colour is for a terminal that will render it, and for no one else"):
    assertEquals(colorAllowed(None, Some("xterm-256color")), true)
    assertEquals(colorAllowed(None, None), true)
    assertEquals(colorAllowed(Some("1"), Some("xterm-256color")), false)
    assertEquals(colorAllowed(None, Some("dumb")), false)

  test("emphasis tints the severity label and leaves every other word as it was written"):
    val warning = "warning: podman runs on 3.0G of memory\n  raise it with `podman machine set`"
    assertEquals(emphasized(warning, color = false), warning)
    assertEquals(
      emphasized(warning, color = true),
      "\u001b[38;5;208mwarning:\u001b[0m podman runs on 3.0G of memory\n  raise it with `podman machine set`",
    )
    // A block has a label per line, and a line that has none keeps its own spelling.
    assertEquals(
      emphasized("error: no\nplain\nwarning: yes", color = true),
      "\u001b[31merror:\u001b[0m no\nplain\n\u001b[38;5;208mwarning:\u001b[0m yes",
    )
    // The label is a prefix, never a word found mid-line: this one is a subprocess's text quoted.
    assertEquals(emphasized("the proxy said warning: x", color = true), "the proxy said warning: x")

  test("a refusal raised while the JVM is shutting down names the interruption first, and waits"):
    assert(!shuttingDown, "a JVM with no shutdown under way reported one")
    // The true case needs a shutdown under way, so it runs in a JVM of its own on this test's
    // classes (FailDuringShutdown). The exit status is the shutdown's, not the refusal's: the
    // refusal's exit blocked indefinitely, and the JVM ended when the hook finished.
    def location(of: Class[?]) = Paths.get(of.getProtectionDomain.getCodeSource.getLocation.toURI).toString
    val classpath = Vector(
      FailDuringShutdown.getClass, HostCommands.getClass, scala.runtime.LazyVals.getClass, classOf[Option[?]],
    ).map(location).distinct.mkString(java.io.File.pathSeparator)
    val jvm = Paths.get(sys.props("java.home"), "bin", "java").toString
    // Native access as the jar's manifest grants it, for the isatty or console-mode call behind
    // colorStderr: this JVM's stderr is a pipe, so the plain labels below are also that call
    // answering for a redirected stream, which sbt's own JVM, run from a console, cannot show.
    // The environment is set so that colorAllowed passes and the call is what decides.
    // What the JVM prints before the first refusal line is its own: _JAVA_OPTIONS echoed back.
    val builder = ProcessBuilder(
      jvm, "--enable-native-access=ALL-UNNAMED", "-cp", classpath, "agentsandbox.launcher.FailDuringShutdown",
    )
    builder.environment().remove("NO_COLOR")
    builder.environment().put("TERM", "xterm-256color")
    val process = builder.start()
    process.getOutputStream.close()
    process.getInputStream.readAllBytes()
    val stagedErr = String(process.getErrorStream.readAllBytes())
    assertEquals(
      stagedErr.linesIterator.dropWhile(!_.startsWith("error:")).toVector,
      Vector(
        "error: the launch was interrupted; the failure below is its consequence, not a fault of its own",
        "error: podman failed",
        "its stderr",
        "hook: removed",
      ),
    )
    assertEquals(process.waitFor(), 130)

  test("every warning and refusal the launcher writes goes through the one label"):
    // warn and fail are where the label is spelled and tinted; a println of its own prints it
    // plain on a terminal and drifts the day the rule changes.
    val printedLabel = """System\.err\.println\(\s*s?"(warning|error):""".r
    val offenders =
      for
        file <- directoryEntries(Paths.get("src", "main", "scala"))
        if file.getFileName.toString != "HostCommands.scala"
        hit <- printedLabel.findFirstIn(Files.readString(file))
      yield s"${file.getFileName}: $hit"
    assertEquals(offenders, Vector.empty)

  // The POSIX-branch resolution tests below build ':'-separated PATH strings out of real
  // directories, which on a Windows runner have their own ':' after the drive letter — the
  // string cannot be built there, not merely the branch untested. The Windows branch has its own
  // test, which runs everywhere.
  private val isWindows = scala.util.Properties.isWin

  test("executables resolve only through absolute PATH entries"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val dir = Files.createTempDirectory("path-resolve").toRealPath()
    val program = dir.resolve("myprogram")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    // `.` and a repository-relative directory are skipped, never searched.
    assertEquals(findOnPath("myprogram", s".:relative/dir:$dir", Os.Linux), Some(program))
    assertEquals(findOnPath("myprogram", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("myprogram", "", Os.Linux), None)

  test("an absolute PATH entry inside the project is skipped, not preferred"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    // The absolute-entry-inside-the-project case (HostCommands.findOnPath's doc, design.md "No
    // repository-controlled host executable resolution").
    val project = Files.createTempDirectory("untrusted-project").toRealPath()
    val shipped = Files.createDirectories(project.resolve("node_modules/.bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val system = Files.createTempDirectory("system-bin").toRealPath()
    val real = system.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)

    // Ahead of the system directory, which is exactly where it would otherwise win.
    assertEquals(findOnPath("podman", s"$shipped:$system", Os.Linux, project), Some(real))
    // Skipped rather than merely deprioritized: with nothing else on PATH there is no fallback.
    assertEquals(findOnPath("podman", shipped.toString, Os.Linux, project), None)
    // A directory that merely shares a prefix with the project is not inside it.
    val sibling = Files.createDirectories(project.resolveSibling(s"${project.getFileName}x"))
    val neighbour = sibling.resolve("podman")
    Files.createFile(neighbour)
    neighbour.toFile.setExecutable(true)
    assertEquals(findOnPath("podman", sibling.toString, Os.Linux, project), Some(neighbour))

  test("an executable symlinked out of the project is skipped, and the real path is returned"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val project = Files.createTempDirectory("untrusted-project").toRealPath()
    val shipped = Files.createDirectories(project.resolve("bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val outside = Files.createTempDirectory("outside-bin").toRealPath()
    Files.createSymbolicLink(outside.resolve("podman"), planted)
    assertEquals(findOnPath("podman", outside.toString, Os.Linux, project), None)

    val elsewhere = Files.createTempDirectory("real-bin").toRealPath()
    val real = elsewhere.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)
    val shim = Files.createTempDirectory("shim-bin").toRealPath()
    Files.createSymbolicLink(shim.resolve("podman"), real)
    assertEquals(findOnPath("podman", shim.toString, Os.Linux, project), Some(real))

  test("Windows resolution appends executable extensions and splits on ;"):
    val dir = Files.createTempDirectory("path-resolve-win").toRealPath()
    val program = dir.resolve("myprogram.exe")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    assertEquals(findOnPath("myprogram", s"relative\\dir;$dir", Os.Windows), Some(program))
    // The bare, extensionless name is not a Windows executable and is never a candidate.
    val bare = Files.createFile(dir.resolve("otherprogram"))
    bare.toFile.setExecutable(true)
    assertEquals(findOnPath("otherprogram", dir.toString, Os.Windows), None)

  test("every script the launcher writes names its own PATH before running anything"):
    val scripts = Vector(
      "mount" -> koAgentFsMountScript("/tmp/backing", "app-abc123def456", "d" * 64, "run-1"),
      "reap" -> koAgentFsReapScript("/usr/bin/podman", "app-abc123def456", "run-1"),
      "unmount" -> koAgentFsUnmountScript("app-abc123def456"),
      "unmount-all" -> koAgentFsUnmountAllScript,
      "reaper" -> ReaperScript,
    )
    scripts.foreach: (name, script) =>
      assertEquals(script.linesIterator.next(), s"export PATH=$ScriptPath", name)
      // Syntax only, by the interpreter that runs it; what a valid script does is each script's
      // own behavioral test.
      if !isWindows then
        val parsed = ProcessBuilder("/bin/sh", "-n", "-c", script).redirectErrorStream(true).start()
        val output = String(parsed.getInputStream.readAllBytes())
        assertEquals(parsed.waitFor(), 0, s"$name does not parse:\n$output")
    // Absolute system directories only: a relative entry is exactly what is kept out.
    assert(
      ScriptPath.split(":").forall(entry => entry.startsWith("/") && entry.length > 1),
      ScriptPath,
    )

  test("a quote-free script keeps its quotes, its newlines, its arguments and the caller's stdin"):
    assume(!isWindows, "runs the receiving shell, which a POSIX host has")
    // The clipboard's response writer reads the exec's stdin, so the script must not arrive on it.
    val script = """printf '%s|%s|' "$1" "$2"
                   |for word in *; do :; done
                   |cat""".stripMargin
    val words = quoteFreeSh(script, "my app/*", "it's \"quoted\"")
    // The wrapper's own words; the arguments after them are the caller's.
    assert(words.take(5).forall(word => !word.contains('"') && !word.contains('\n')), words)
    val process = ProcessBuilder(words*).redirectErrorStream(true).start()
    process.getOutputStream.write("from stdin".getBytes)
    process.getOutputStream.close()
    val output = String(process.getInputStream.readAllBytes())
    assertEquals(process.waitFor(), 0, output)
    assertEquals(output, "my app/*|it's \"quoted\"|from stdin")
    // The clipboard scripts, which a Windows launcher passes the same way, take no argument.
    for clipboard <- Seq(ClipboardBroker.sandboxRequestReader(), ClipboardBroker.sandboxResponseWriter()) do
      assert(quoteFreeSh(clipboard).forall(word => !word.contains('"') && !word.contains('\n')))

object PodmanResolutionProbe:
  def main(args: Array[String]): Unit =
    println(podmanRuns)
    println(podmanVersion())
    println(podman)
    println(podmanRuns)
    println(podmanVersion())
