// Host command tests cover executable resolution, the PATH of generated scripts, launcher diagnostics and the sizes
// that the diagnostics print.
// FileHelperTest and DirectoryStreamsTest cover the shared file operations.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import HostCommands.*
import FileHelper.*
import KoAgentFs.*
import SandboxLifecycle.*

class HostCommandsTest extends munit.FunSuite:

  test("sizes print as `numfmt --to=iec` prints them, the rule of df, du and ls -h"):
    // Each expected string is numfmt's own output for the same byte count.
    assertEquals(humanBytes(0), "0")
    assertEquals(humanBytes(1023), "1023")
    assertEquals(humanBytes(1024), "1.0K")
    assertEquals(humanBytes(1025), "1.1K")
    assertEquals(humanBytes(1536), "1.5K")
    assertEquals(humanBytes(10188), "10K")
    assertEquals(humanBytes(10240), "10K")
    assertEquals(humanBytes(10241), "11K")
    assertEquals(humanBytes(1047552), "1023K")
    assertEquals(humanBytes(1048064), "1.0M")
    assertEquals(humanBytes(1048575), "1.0M")
    assertEquals(humanBytes(1073321984), "1.0G")
    assertEquals(humanBytes(11381243904L), "11G")
    assertEquals(humanBytes(1L << 40), "1.0T")
    assertEquals(humanBytes(3L << 40), "3.0T")
    assertEquals(humanBytes(3L << 50), "3.0P")
    assertEquals(humanBytes((1L << 62) - 1), "4.0E")
    assertEquals(humanBytes(Long.MaxValue), "8.0E")
    // humanPair prints a part in its whole's unit and rounds the part by the same rule at that unit.
    assertEquals(humanPair(237L << 20, 11381243904L), ("0.3", "11G"))
    assertEquals(humanPair(8L << 20, 256L << 20), ("8.0", "256M"))
    assertEquals(humanPair(15L << 20, 256L << 20), ("15", "256M"))
    assertEquals(humanPair(0, 256L << 20), ("0.0", "256M"))
    assertEquals(humanPair(1048064, 1048064), ("1.0", "1.0M"))

  test("a share line says the percentage first and the figure the thresholds act on beside it"):
    assertEquals(shareLine("storage", (9367L << 30) / 10, (16L << 40) / 10, "free"), "storage: 57% (937G) free")
    assertEquals(shareLine("memory", 6L << 30, 8L << 30, "available"), "memory: 75% (6.0G) available")
    // The tint wraps the figure alone, so the words stay readable where the escape does not render.
    assertEquals(
      shareLine("memory", 6L << 30, 8L << 30, "available", "<" + _ + ">"),
      "memory: <75% (6.0G)> available",
    )

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
      for label <- Seq("log dir", "egress log dir", "egress tls ca") do
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
    assertEquals(pathLine("log dir", posix, Os.Linux, _ => None), "log dir: '/var/log/$USER.log'")

  test("Windows paths abbreviate only the user profile, as PowerShell's ~"):
    for
      user <- Seq("kenichi", "test user", "test&user", "test(user)", "test^user", "test;user", "test'user")
      name <- Seq("proxy-run.log", "run-on-host-run.log")
    do
      val home = s"C:\\Users\\$user"
      val environment = Map("USERPROFILE" -> home, "HOME" -> "C:\\elsewhere").get
      val relative = s"AppData\\Local\\ko-agent-sandbox\\log\\$name"
      for profile <- Seq(home, s"$home\\", home.toUpperCase) do
        assertEquals(
          displayPath(Paths.get(s"$home\\$relative"), Os.Windows, Map("USERPROFILE" -> profile).get),
          s"~\\$relative",
        )
      assertEquals(displayPath(Paths.get(home), Os.Windows, environment), "~")
      assertEquals(displayPath(Paths.get(s"$home\\My Projects"), Os.Windows, environment), "\"~\\My Projects\"")
      assertEquals(
        pathLine("log dir", Paths.get(s"$home\\$$x"), Os.Windows, environment),
        "log dir (PowerShell): '~\\$x'",
      )
      for missing <- Seq(None, Some(""), Some("Users\\me")) do
        assertEquals(displayPath(Paths.get(s"D:\\$relative"), Os.Windows, _ => missing), s"D:\\$relative")
    // The label follows the displayed text: a profile's `$` that the ~ replaces needs no PowerShell literal.
    val dollarProfile = Map("USERPROFILE" -> "C:\\Users\\a$b").get
    val underDollarProfile = Paths.get("C:\\Users\\a$b\\logs")
    assertEquals(pathLine("log dir", underDollarProfile, Os.Windows, dollarProfile), "log dir: ~\\logs")
    assertEquals(pathInline(underDollarProfile, Os.Windows, dollarProfile), "~\\logs")

  test("Windows paths outside the user profile quote spaces and separators for cmd.exe and PowerShell"):
    for
      user <- Seq("kenichi", "test user", "test&user", "test(user)", "test^user", "test;user", "test'user")
      name <- Seq("proxy-run.log", "run-on-host-run.log")
    do
      val home = s"C:\\Users\\$user"
      val environment = Map("USERPROFILE" -> home).get
      for path <- Seq(Paths.get(s"D:\\$user\\log\\$name"), Paths.get(s"$home-other\\log\\$name")) do
        val expected = if user == "kenichi" then path.toString else s"\"$path\""
        assertEquals(displayPath(path, Os.Windows, environment), expected)
        for label <- Seq("log dir", "egress log dir", "egress tls ca") do
          assertEquals(pathLine(label, path, Os.Windows, environment), s"$label: $expected")
        assertEquals(pathLine("==>", path, Os.Windows, environment, separator = " "), s"==> $expected")

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
      label <- Seq("log dir", "egress log dir", "egress tls ca")
    do
      val path = Paths.get(s"C:\\logs\\$name")
      val expected = s"'C:\\logs\\$escaped'"
      assertEquals(displayPath(path, Os.Windows), expected)
      assertEquals(pathLine(label, path, Os.Windows), s"$label (PowerShell): $expected")
      assertEquals(pathLine("==>", path, Os.Windows, separator = " "), s"==> (PowerShell) $expected")
      // Inside a sentence, the label follows the path. A tint covers the path alone.
      assertEquals(pathInline(path, Os.Windows), s"$expected (PowerShell)")
      assertEquals(pathLine(label, path, Os.Windows, tint = text => s"<$text>"), s"$label (PowerShell): <$expected>")

  test("only an explicit yes is consent"):
    assert(consented(Some("y")))
    assert(consented(Some("Y")))
    assert(consented(Some(" YES ")))
    assert(!consented(Some("")))
    assert(!consented(Some("n")))
    assert(!consented(Some("yeah")))
    assert(!consented(None))

  test("color is for a terminal that will render it, and for no one else"):
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
    // Each line of a block carries its own label, and a line without a label keeps its own spelling.
    assertEquals(
      emphasized("error: no\nplain\nwarning: yes", color = true),
      "\u001b[31merror:\u001b[0m no\nplain\n\u001b[38;5;208mwarning:\u001b[0m yes",
    )
    // A label is a line prefix, never a word in the middle of a line. This line quotes a subprocess's text.
    assertEquals(emphasized("the proxy said warning: x", color = true), "the proxy said warning: x")

  test("a span tinted inside another ends its own tint, and the outer one resumes after it"):
    val (orange, gray, off) = ("\u001b[38;5;208m", "\u001b[38;5;245m", "\u001b[0m")
    assertEquals(
      weakened(s"a ${lookedUp("b", color = true)} c ${lookedUp("d", color = true)}", color = true),
      s"${orange}a ${gray}b$off$orange c ${gray}d$off$orange$off",
    )
    assertEquals(weakened(s"a ${lookedUp("b", color = false)}", color = false), "a b")

  test("a refusal raised while the JVM is shutting down names the interruption first, and waits"):
    assert(!shuttingDown, "a JVM with no shutdown under way reported one")
    // The true case needs a shutdown under way, so the case runs in a JVM of its own on this test's classes
    // (FailDuringShutdown).
    // - The exit status is the shutdown's, not the refusal's. The refusal's exit blocked indefinitely, and the JVM
    //   ended when the hook finished.
    // - ownJvm grants native access for the isatty or console-mode call behind colorStderr. The child JVM's stderr is a
    //   pipe, so the plain labels below also show that call answering for a redirected stream. sbt's own JVM, run from
    //   a console, cannot show that answer.
    // - The test sets the environment so that colorAllowed passes and the isatty or console-mode call decides.
    // - The lines before the first refusal line are the JVM's own output: it echoes _JAVA_OPTIONS back.
    val builder = ownJvm(FailDuringShutdown)
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

  test("a background step gives its result or its exception, and a refusal meanwhile waits for it"):
    assertEquals(inBackground("sum")(1 + 2)(), 3)
    val failing = inBackground("failing")(throw IllegalArgumentException("no answer"))
    assertEquals(intercept[IllegalArgumentException](failing()).getMessage, "no answer")
    // The refusal exits the JVM, so the refusal runs in a JVM of its own (RefuseDuringBackgroundStep).
    val process = ownJvm(RefuseDuringBackgroundStep).start()
    process.getOutputStream.close()
    process.getInputStream.readAllBytes()
    val err = String(process.getErrorStream.readAllBytes())
    assertEquals(
      err.linesIterator.dropWhile(!_.startsWith("error:")).toVector,
      Vector("error: refused", "step: finished"),
    )
    assertEquals(process.waitFor(), 1)

  test("a background step a shutdown overtakes does not start"):
    // The shutdown ends the JVM, so each case runs in a JVM of its own (BackgroundStepDuringShutdown).
    def stepLines(mode: String): Vector[String] =
      val process = ownJvm(BackgroundStepDuringShutdown, mode).start()
      process.getOutputStream.close()
      process.getInputStream.readAllBytes()
      val err = String(process.getErrorStream.readAllBytes())
      assertEquals(process.waitFor(), 3, err)
      err.linesIterator.filter(_.startsWith("step:")).toVector
    assertEquals(stepLines("begun"), Vector.empty)
    assertEquals(stepLines("window"), Vector.empty)

  test("every warning and refusal the launcher writes goes through the one label"):
    // warn and fail spell and tint the label. A println of its own prints the label plain on a terminal, and its
    // spelling drifts on the day the rule changes.
    val printedLabel = """System\.err\.println\(\s*s?"(warning|error):""".r
    val offenders =
      for
        file <- directoryEntries(Paths.get("src", "main", "scala"))
        if file.getFileName.toString != "HostCommands.scala"
        hit <- printedLabel.findFirstIn(Files.readString(file))
      yield s"${file.getFileName}: $hit"
    assertEquals(offenders, Vector.empty)

  /** A JVM of its own that runs `fixture`'s main on this test's classes, with native access as the jar's manifest
    * grants it. */
  private def ownJvm(fixture: Any, args: String*): ProcessBuilder =
    def location(of: Class[?]) = Paths.get(of.getProtectionDomain.getCodeSource.getLocation.toURI).toString
    val classpath = Vector(fixture.getClass, HostCommands.getClass, scala.runtime.LazyVals.getClass, classOf[Option[?]])
      .map(location).distinct.mkString(java.io.File.pathSeparator)
    val jvm = Paths.get(sys.props("java.home"), "bin", "java").toString
    val main = fixture.getClass.getName.stripSuffix("$")
    ProcessBuilder((Vector(jvm, "--enable-native-access=ALL-UNNAMED", "-cp", classpath, main) ++ args)*)

  // The resolution tests of the POSIX branch below build ':'-separated PATH strings out of real directories. On a
  // Windows host, those directories have their own ':' after the drive letter, so the string cannot be built there at
  // all; the branch is not merely untested. The Windows branch has its own test, which runs everywhere.
  private val isWindows = scala.util.Properties.isWin

  test("executables resolve only through absolute PATH entries"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val dir = Files.createTempDirectory("path-resolve").toRealPath()
    val program = dir.resolve("myprogram")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    // Resolution skips `.` and a repository-relative directory and never searches them.
    assertEquals(findOnPath("myprogram", s".:relative/dir:$dir", Os.Linux), Some(program))
    assertEquals(findOnPath("myprogram", ".:relative/dir", Os.Linux), None)
    assertEquals(findOnPath("absent", dir.toString, Os.Linux), None)
    assertEquals(findOnPath("myprogram", "", Os.Linux), None)

  test("an absolute PATH entry inside the workspace is skipped, not preferred"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    // The case of an absolute entry inside the workspace (HostCommands.findOnPath's doc; `doc/design.md`, "No
    // repository-controlled host executable resolution").
    val workspace = Files.createTempDirectory("untrusted-workspace").toRealPath()
    val shipped = Files.createDirectories(workspace.resolve("node_modules/.bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val system = Files.createTempDirectory("system-bin").toRealPath()
    val real = system.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)

    // The workspace entry comes ahead of the system directory, which is exactly where it would otherwise win.
    assertEquals(findOnPath("podman", s"$shipped:$system", Os.Linux, workspace), Some(real))
    // Resolution skips the workspace entry rather than merely deprioritizing it: with nothing else on PATH, it finds
    // nothing.
    assertEquals(findOnPath("podman", shipped.toString, Os.Linux, workspace), None)
    // A directory that merely shares a prefix with the workspace is not inside it.
    val sibling = Files.createDirectories(workspace.resolveSibling(s"${workspace.getFileName}x"))
    val neighbour = sibling.resolve("podman")
    Files.createFile(neighbour)
    neighbour.toFile.setExecutable(true)
    assertEquals(findOnPath("podman", sibling.toString, Os.Linux, workspace), Some(neighbour))

  test("an executable symlinked out of the workspace is skipped, and the real path is returned"):
    assume(!isWindows, "POSIX PATH strings cannot hold drive-letter directories")
    val workspace = Files.createTempDirectory("untrusted-workspace").toRealPath()
    val shipped = Files.createDirectories(workspace.resolve("bin"))
    val planted = shipped.resolve("podman")
    Files.createFile(planted)
    planted.toFile.setExecutable(true)

    val outside = Files.createTempDirectory("outside-bin").toRealPath()
    Files.createSymbolicLink(outside.resolve("podman"), planted)
    assertEquals(findOnPath("podman", outside.toString, Os.Linux, workspace), None)

    val elsewhere = Files.createTempDirectory("real-bin").toRealPath()
    val real = elsewhere.resolve("podman")
    Files.createFile(real)
    real.toFile.setExecutable(true)
    val shim = Files.createTempDirectory("shim-bin").toRealPath()
    Files.createSymbolicLink(shim.resolve("podman"), real)
    assertEquals(findOnPath("podman", shim.toString, Os.Linux, workspace), Some(real))

  test("Windows resolution appends executable extensions and splits on ;"):
    val dir = Files.createTempDirectory("path-resolve-win").toRealPath()
    val program = dir.resolve("myprogram.exe")
    Files.createFile(program)
    program.toFile.setExecutable(true)
    assertEquals(findOnPath("myprogram", s"relative\\dir;$dir", Os.Windows), Some(program))
    // A bare name without an extension is not a Windows executable, so resolution never considers it.
    val bare = Files.createFile(dir.resolve("otherprogram"))
    bare.toFile.setExecutable(true)
    assertEquals(findOnPath("otherprogram", dir.toString, Os.Windows), None)

  test("every script the launcher writes names its own PATH before running anything"):
    val scripts = Vector(
      "mount" -> koAgentFsMountScript("/tmp/backing", "app-abc123def456", "d" * 64, "run-1", "host-view /\n"),
      "resolve" -> koAgentFsResolveScript("/tmp/backing", "app-abc123def456", "d" * 64, "host-view /\n"),
      "reap" -> koAgentFsReapScript("/usr/bin/podman", "app-abc123def456", "run-1"),
      "unmount" -> koAgentFsUnmountScript("app-abc123def456"),
      "unmount-all" -> koAgentFsUnmountAllScript,
      "reaper" -> ReaperScript,
    )
    scripts.foreach: (name, script) =>
      assertEquals(script.linesIterator.next(), s"export PATH=$ScriptPath", name)
      // The interpreter that runs the script checks its syntax only. Each script's own behavioral test checks what a
      // valid script does.
      if !isWindows then
        val parsed = ProcessBuilder("/bin/sh", "-n", "-c", script).redirectErrorStream(true).start()
        val output = String(parsed.getInputStream.readAllBytes())
        assertEquals(parsed.waitFor(), 0, s"$name does not parse:\n$output")
    // ScriptPath holds absolute system directories only, because a relative entry is exactly what it keeps out.
    assert(
      ScriptPath.split(":").forall(entry => entry.startsWith("/") && entry.length > 1),
      ScriptPath,
    )
