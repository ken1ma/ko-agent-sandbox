// The image's ENTRYPOINT, run as the shell script it is: what it seeds into a persistent volume
// that is fresh, that predates an agent, or that two sessions open at once, and the trust entry it
// records for the project — the working directory — in each agent's own file.

package agentsandbox.launcher

import java.nio.ByteBuffer
import java.nio.file.{Files, Path}
import java.nio.file.attribute.UserDefinedFileAttributeView
import scala.jdk.CollectionConverters.*

class SandboxEntrypointTest extends munit.FunSuite:

  private val script = Path.of("container/ko-agent-sandbox/sandbox-entrypoint").toAbsolutePath
  private val sh = Path.of("/bin/sh")
  private lazy val gnuMv =
    try
      val process = ProcessBuilder("mv", "--version").redirectErrorStream(true).start()
      val output = String(process.getInputStream.readAllBytes())
      process.waitFor() == 0 && output.contains("GNU coreutils")
    catch case _: java.io.IOException => false
  private lazy val jq =
    try ProcessBuilder("jq", "--version").redirectErrorStream(true).start().waitFor() == 0
    catch case _: java.io.IOException => false

  private def fixture(): (Path, Path) =
    // `mv -T` is GNU coreutils' and `jq` is the image's: the script runs only in the Debian image,
    // and so does this suite's host.
    assume(Files.isExecutable(sh) && gnuMv && jq, "runs the entrypoint under /bin/sh with GNU mv and jq")
    val root = Files.createTempDirectory("sandbox-entrypoint")
    val seed = Files.createDirectories(root.resolve("seed"))
    Vector("claude", "codex", "antigravity", "kiro", "copilot", "opencode").foreach: agent =>
      Files.createDirectory(seed.resolve(agent))
      Files.writeString(seed.resolve(agent).resolve("seeded"), agent)
    Files.createSymbolicLink(seed.resolve("copilot").resolve("copilot-instructions.md"), script)
    // opencode's seed has depth: the link sits in a subdirectory.
    Files.createDirectory(seed.resolve("opencode").resolve("config"))
    Files.createSymbolicLink(seed.resolve("opencode").resolve("config").resolve("AGENTS.md"), script)
    val home = Files.createDirectories(root.resolve("home"))
    Files.createDirectory(home.resolve("persistent-volume"))
    (seed, home)

  /**
   * Starts the entrypoint with the fixture's seed and HOME; the command it execs prints its
   * arguments. `/proc` is the healthy fixture unless a test hands over its own, so the machine
   * this suite runs on never decides whether a warning prints.
   */
  private def start(
    seed: Path,
    home: Path,
    proc: Path = healthyProc(),
    path: Option[Path] = None,
    // The project, where the launcher starts the session (--workdir); the entrypoint reads it
    // from its working directory.
    project: Path = Project,
  ): Process =
    val builder =
      ProcessBuilder(sh.toString, script.toString, "sh", "-c", "printf '%s ' \"$0\" \"$@\"", "a", "b c")
    builder.directory(project.toFile)
    builder.environment.put("SANDBOX_VOLUME_SEED", seed.toString)
    builder.environment.put("HOME", home.toString)
    builder.environment.put("SANDBOX_PROC", proc.toString)
    path.foreach(dir => builder.environment.put("PATH", dir.toString + ":" + System.getenv("PATH")))
    builder.redirectErrorStream(true)
    builder.start()

  /** A `/proc` in kB, as the kernel writes it, with the pressure file present or absent. */
  private def proc(
    available: Long,
    total: Long = 16L << 20,
    swapUsed: Long = 0,
    pressure: Option[String] = None,
  ): Path =
    val root = Files.createTempDirectory("sandbox-entrypoint-proc")
    Files.writeString(
      root.resolve("meminfo"),
      s"""MemTotal:       $total kB
         |MemFree:        ${available / 2} kB
         |MemAvailable:   $available kB
         |SwapTotal:      ${4L << 20} kB
         |SwapFree:       ${(4L << 20) - swapUsed} kB
         |""".stripMargin,
    )
    pressure.foreach: line =>
      Files.createDirectory(root.resolve("pressure"))
      Files.writeString(
        root.resolve("pressure").resolve("memory"),
        line + "\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
      )
    root

  private def healthyProc(): Path =
    proc(available = 8L << 20, pressure = Some("some avg10=0.00 avg60=0.00 avg300=0.00 total=0"))

  /** A `df` answering with the given free kB, on a PATH entry to put before the real one. */
  private def fakeDf(availableKb: Long): Path =
    val dir = Files.createTempDirectory("sandbox-entrypoint-bin")
    val df = dir.resolve("df")
    Files.writeString(
      df,
      s"#!/bin/sh\necho 'Filesystem 1024-blocks Used Available Capacity Mounted on'\n" +
        s"echo 'vda 100 1 $availableKb 1% /'\n",
    )
    df.toFile.setExecutable(true)
    dir

  private def finish(process: Process): (Int, String) =
    val output = String(process.getInputStream.readAllBytes())
    (process.waitFor(), output)

  private def run(seed: Path, home: Path, project: Path = Project): (Int, String) =
    finish(start(seed, home, project = project))

  /** A project directory with a name every agent's file must quote: a space, and for Codex a
    * double quote and a backslash, the two characters a TOML basic string escapes. */
  private lazy val Project: Path =
    Files.createDirectories(Files.createTempDirectory("sandbox-entrypoint-project").resolve("my \"app\" \\ src"))

  /** Every JSON file the suite reads, canonicalized with jq: keys sorted, no whitespace, after
    * `filter`. */
  private def parsed(file: Path, filter: String = "."): String =
    val process = ProcessBuilder("jq", "-c", "-S", filter, file.toString).redirectErrorStream(true).start()
    val output = String(process.getInputStream.readAllBytes()).trim
    assertEquals(process.waitFor(), 0, output)
    output

  private def trustFiles(home: Path): (Path, Path, Path, Path) =
    val volume = home.resolve("persistent-volume")
    (
      volume.resolve("claude/.claude.json"),
      volume.resolve("antigravity/antigravity-cli/settings.json"),
      volume.resolve("copilot/config.json"),
      volume.resolve("codex/config.toml"),
    )

  private def entries(volume: Path): Set[String] =
    FileHelper.directoryEntries(volume).map(_.getFileName.toString).toSet

  private def setUserAttribute(path: Path, name: String): Unit =
    val attributes = Files.getFileAttributeView(path, classOf[UserDefinedFileAttributeView])
    assume(attributes != null, "the test filesystem supports user-defined attributes")
    try attributes.write(name, ByteBuffer.wrap(Array[Byte](1)))
    catch
      case _: UnsupportedOperationException | _: java.io.IOException =>
        assume(false, "the test filesystem supports user-defined attributes")

  private def userAttributes(path: Path): Set[String] =
    val attributes = Files.getFileAttributeView(path, classOf[UserDefinedFileAttributeView])
    Option(attributes).fold(Set.empty[String])(_.list().asScala.toSet)

  test("a fresh volume receives every seed directory, and the command runs with its arguments intact"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")
    val volume = home.resolve("persistent-volume")
    assertEquals(entries(volume), Set("claude", "codex", "antigravity", "kiro", "copilot", "opencode"))
    assertEquals(Files.readString(volume.resolve("codex").resolve("seeded")), "codex")
    assert(Files.isSymbolicLink(volume.resolve("copilot").resolve("copilot-instructions.md")))
    assert(Files.isSymbolicLink(volume.resolve("opencode").resolve("config").resolve("AGENTS.md")))

  test("a volume from an older image gets only the directories it lacks; the rest is untouched"):
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    Files.createDirectory(volume.resolve("claude"))
    Files.writeString(volume.resolve("claude").resolve("seeded"), "login state")
    Files.createDirectory(volume.resolve("codex"))  // present but empty: still the agent's
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(Files.readString(volume.resolve("claude").resolve("seeded")), "login state")
    // Only the project's trust entry joins the agent's own directory.
    assertEquals(entries(volume.resolve("codex")), Set("config.toml"))
    assertEquals(Files.readString(volume.resolve("copilot").resolve("seeded")), "copilot")

  test("seed metadata does not escape into the cross-session volume"):
    val (seed, home) = fixture()
    val privateAttribute = "ko-agent-sandbox-private-label"
    setUserAttribute(seed.resolve("copilot"), privateAttribute)
    setUserAttribute(seed.resolve("copilot").resolve("seeded"), privateAttribute)
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    val copied = home.resolve("persistent-volume").resolve("copilot")
    assert(!userAttributes(copied).contains(privateAttribute))
    assert(!userAttributes(copied.resolve("seeded")).contains(privateAttribute))

  test("sessions seeding one volume at once all succeed, and leave one copy and no staging behind"):
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    // Two projects, so the launches also race on a shared volume's files, not only on the seed.
    val other = Files.createTempDirectory("sandbox-entrypoint-other")
    val results =
      (1 to 20).toVector.map(i => start(seed, home, project = if i % 2 == 0 then other else Project)).map(finish)
    results.foreach((status, output) => assertEquals(status, 0, output))
    assertEquals(entries(volume), Set("claude", "codex", "antigravity", "kiro", "copilot", "opencode"))
    assertEquals(entries(volume.resolve("copilot")), Set("seeded", "copilot-instructions.md", "config.json"))
    // Every launch's entry survives the others', once: no lost update, no second list element,
    // and one Codex table per project, which a second would make invalid TOML.
    val (claude, antigravity, copilot, codex) = trustFiles(home)
    val quoted = "\"" + Project.toString.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    assertEquals(
      parsed(claude),
      s"""{"projects":{"$other":{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true},""" +
        s"""$quoted:{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true}}}""",
    )
    // The lists' order is the launches' order under the lock, so each is compared sorted.
    assertEquals(parsed(antigravity, ".trustedWorkspaces |= sort"), s"""{"trustedWorkspaces":["$other",$quoted]}""")
    assertEquals(parsed(copilot, ".trustedFolders |= sort"), s"""{"trustedFolders":["$other",$quoted]}""")
    val tables = Files.readString(codex).linesIterator.filter(_.startsWith("[projects.")).toVector
    assertEquals(tables.sorted, Vector(s"[projects.$quoted]", s"""[projects."$other"]""").sorted)

  test("a home with no persistent-volume — a container run by hand, not a session — still runs the command"):
    val (seed, home) = fixture()
    Files.delete(home.resolve("persistent-volume"))
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")
    assert(!Files.exists(home.resolve("persistent-volume")))

  test("a healthy machine prints nothing before the command"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")

  test("a machine short of memory, swapping, stalled, or out of disk is said before the command, once"):
    val (seed, home) = fixture()
    // Sizes as numfmt --to=iec prints them, at the rule's edges: 65 MiB in its 10.6 GiB total's
    // unit, 9.95 MiB of swap rounding up to a whole 10, and 1023.5 MiB of disk carrying to 1.0G.
    val failing = proc(
      available = 65L << 10,
      total = (106L << 20) / 10,
      swapUsed = 10188,
      pressure = Some("some avg10=40.00 avg60=25.50 avg300=3.00 total=1"),
    )
    val (status, output) = finish(start(seed, home, failing, Some(fakeDf(1048064))))
    assertEquals(status, 0, output)
    assert(output.startsWith("warning: the machine podman runs on is under pressure"), output)
    assert(output.contains("  0.1 of 11G memory available\n"), output)
    assert(output.contains("  10M of swap in use\n"), output)
    assert(output.contains("  memory pressure: tasks stalled on memory 25.50% of the last minute\n"), output)
    assert(output.contains("  1.0G of disk left on the machine\n"), output)
    assert(output.contains("podman machine set --memory"), output)
    // No terminal on stdin, so no hold: the command still ran.
    assert(!output.contains("[Y/n]"), output)
    assert(output.endsWith("a b c "), output)

  test("swap left over from pressure that has passed is not pressure"):
    val (seed, home) = fixture()
    val lingering = proc(available = 8L << 20, total = 16L << 20, swapUsed = 1L << 20)
    val (status, output) = finish(start(seed, home, lingering))
    assertEquals(status, 0, output)
    assertEquals(output, "a b c ")
    // The same swap with memory tight now — under a quarter available, not yet under 1 GiB — is.
    val tight = proc(available = 3L << 20, total = 16L << 20, swapUsed = 1L << 20)
    val (_, warned) = finish(start(seed, home, tight))
    assert(warned.contains("  1.0G of swap in use\n"), warned)
    assert(!warned.contains("memory available"), warned)

  test("a pressure file the kernel refuses to serve, or lacks, costs only its line"):
    val (seed, home) = fixture()
    val refused = proc(available = 512L << 10, pressure = Some("x"))
    refused.resolve("pressure").resolve("memory").toFile.setReadable(false)
    Vector(refused, proc(available = 512L << 10)).foreach: failing =>
      val (status, output) = finish(start(seed, home, failing))
      assertEquals(status, 0, output)
      assert(output.contains("memory available"), output)
      assert(!output.contains("memory pressure"), output)

  test("a fresh volume records the project as trusted for every agent that asks, keyed by its path"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home)
    assertEquals(status, 0, output)
    val (claude, antigravity, copilot, codex) = trustFiles(home)
    val quoted = "\"" + Project.toString.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    assertEquals(
      parsed(claude),
      s"""{"projects":{$quoted:{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true}}}""",
    )
    assertEquals(parsed(antigravity), s"""{"trustedWorkspaces":[$quoted]}""")
    assertEquals(parsed(copilot), s"""{"trustedFolders":[$quoted]}""")
    // TOML's basic string escapes the same two characters JSON does.
    assertEquals(Files.readString(codex), s"\n[projects.$quoted]\ntrust_level = \"trusted\"\n")

  test("the trust entry joins what the agent has written, and is written once"):
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    val (claude, antigravity, copilot, codex) = trustFiles(home)
    // Agent state around the entry: another project's entry, keys of the agent's own, a list the
    // agent has ordered. The directories exist, so they are the agent's: edited, never seeded.
    Files.createDirectories(claude.getParent)
    Files.writeString(
      claude,
      """{"oauthAccount":{"emailAddress":"me@example.com"},""" +
        """"projects":{"/Users/me/other":{"hasTrustDialogAccepted":true}}}""",
    )
    Files.createDirectories(antigravity.getParent)
    Files.writeString(antigravity, """{"toolPermission":"always-proceed","trustedWorkspaces":["/Users/me/other"]}""")
    Files.createDirectories(copilot.getParent)
    Files.writeString(copilot, """{"trustedFolders":["/Users/me/zzz","/Users/me/other"]}""")
    Files.createDirectories(codex.getParent)
    Files.writeString(codex, "model = \"o3\"\n\n[projects.\"/Users/me/other\"]\ntrust_level = \"trusted\"\n")
    val simple = Files.createTempDirectory("sandbox-entrypoint-simple")
    val (status, output) = run(seed, home, simple)
    assertEquals(status, 0, output)
    val first = Vector(claude, antigravity, copilot).map(parsed(_)) :+ Files.readString(codex)
    assertEquals(
      first(0),
      """{"oauthAccount":{"emailAddress":"me@example.com"},""" +
        """"projects":{"/Users/me/other":{"hasTrustDialogAccepted":true},""" +
        s""""$simple":{"hasCompletedProjectOnboarding":true,"hasTrustDialogAccepted":true}}}""",
    )
    assertEquals(first(1), s"""{"toolPermission":"always-proceed","trustedWorkspaces":["/Users/me/other","$simple"]}""")
    assertEquals(first(2), s"""{"trustedFolders":["/Users/me/zzz","/Users/me/other","$simple"]}""")
    assertEquals(
      first(3),
      "model = \"o3\"\n\n[projects.\"/Users/me/other\"]\ntrust_level = \"trusted\"\n" +
        s"\n[projects.\"$simple\"]\ntrust_level = \"trusted\"\n",
    )
    // A second launch of the same project changes nothing: no second list element, no second table,
    // and no staging file left beside the agent's.
    val (again, output2) = run(seed, home, simple)
    assertEquals(again, 0, output2)
    assertEquals(Vector(claude, antigravity, copilot).map(parsed(_)) :+ Files.readString(codex), first)
    assertEquals(entries(volume.resolve("claude")), Set(".claude.json"))

  test("Codex's table is found in every spelling, and another trust level is left as written"):
    val (seed, home) = fixture()
    val (_, _, _, codex) = trustFiles(home)
    Files.createDirectories(codex.getParent)
    val simple = Files.createTempDirectory("sandbox-entrypoint-simple")
    // A literal-string key, which a text search for the basic-string spelling would miss and then
    // define twice.
    Files.writeString(codex, s"[projects.'$simple']\ntrust_level = \"trusted\"\n")
    val (status, output) = run(seed, home, simple)
    assertEquals(status, 0, output)
    assertEquals(Files.readString(codex), s"[projects.'$simple']\ntrust_level = \"trusted\"\n")
    // An inline table under [projects], the third spelling.
    Files.writeString(codex, s"[projects]\n\"$simple\" = { trust_level = \"trusted\" }\n")
    val (inline, inlineOutput) = run(seed, home, simple)
    assertEquals(inline, 0, inlineOutput)
    assertEquals(Files.readString(codex), s"[projects]\n\"$simple\" = { trust_level = \"trusted\" }\n")
    // A level Codex or the user set is theirs; the entrypoint says so rather than overriding it.
    Files.writeString(codex, s"[projects.\"$simple\"]\ntrust_level = \"untrusted\"\n")
    val (kept, keptOutput) = run(seed, home, simple)
    assertEquals(kept, 0, keptOutput)
    assertEquals(Files.readString(codex), s"[projects.\"$simple\"]\ntrust_level = \"untrusted\"\n")
    assert(keptOutput.contains(s"marks $simple untrusted"), keptOutput)
    // An inline `projects` table cannot take a table outside its braces: the document the append
    // would make is parsed first, and the file is left as written, with a warning — empty, and
    // holding another project.
    for inline <- Vector("projects = {}\n", "projects = { \"/Users/me/other\" = { trust_level = \"trusted\" } }\n") do
      Files.writeString(codex, inline)
      val (status, output) = run(seed, home, simple)
      assertEquals(status, 0, output)
      assertEquals(Files.readString(codex), inline)
      assert(output.contains("inline table"), output)
    // A file that is not TOML is left alone with a warning.
    Files.writeString(codex, "[projects\n")
    val (invalid, invalidOutput) = run(seed, home, simple)
    assertEquals(invalid, 0, invalidOutput)
    assertEquals(Files.readString(codex), "[projects\n")
    assert(invalidOutput.contains("warning: could not record"), invalidOutput)

  test("an agent directory the session cannot write costs a warning, not the launch"):
    assume(System.getProperty("user.name") != "root", "root writes anywhere")
    val (seed, home) = fixture()
    val volume = home.resolve("persistent-volume")
    val claude = Files.createDirectory(volume.resolve("claude"))
    claude.toFile.setWritable(false, false)
    try
      val (status, output) = run(seed, home)
      assertEquals(status, 0, output)
      assert(output.contains(s"warning: could not record $Project as trusted in $claude/.claude.json"), output)
      assert(output.endsWith("a b c "), output)
      // The other agents' entries were still recorded.
      val (_, _, copilot, codex) = trustFiles(home)
      assert(Files.exists(copilot) && Files.exists(codex))
    finally claude.toFile.setWritable(true, true)

  test("Copilot's comment lines above its JSON are read past, and its other keys kept"):
    val (seed, home) = fixture()
    val (_, _, copilot, _) = trustFiles(home)
    Files.createDirectories(copilot.getParent)
    // As Copilot writes the file (measured 2026-09-18): two comment lines, then the object.
    Files.writeString(
      copilot,
      "// User settings belong in settings.json.\n// This file is managed automatically.\n" +
        """{"trustedFolders":["/Users/me/other"],"firstLaunchAt":"2026-03-11T00:00:00.000Z",""" +
        """"appTipShown":true}""" + "\n",
    )
    val simple = Files.createTempDirectory("sandbox-entrypoint-simple")
    val (status, output) = run(seed, home, simple)
    assertEquals(status, 0, output)
    assert(!output.contains("warning"), output)
    assertEquals(
      parsed(copilot),
      s"""{"appTipShown":true,"firstLaunchAt":"2026-03-11T00:00:00.000Z",""" +
        s""""trustedFolders":["/Users/me/other","$simple"]}""",
    )

  test("a file the agent left unreadable or unparsable costs a warning, not the launch nor the file"):
    val (seed, home) = fixture()
    val (claude, _, copilot, _) = trustFiles(home)
    Files.createDirectories(claude.getParent)
    Files.writeString(claude, "{ not json")
    // Unreadable, in a writable directory: a rename over it would leave an empty file where the
    // agent's state was.
    assume(System.getProperty("user.name") != "root", "root reads anywhere")
    Files.createDirectories(copilot.getParent)
    Files.writeString(copilot, """{"trustedFolders":["/Users/me/other"]}""")
    copilot.toFile.setReadable(false, false)
    try
      val (status, output) = run(seed, home)
      assertEquals(status, 0, output)
      assert(output.contains(s"warning: could not record $Project as trusted in $claude"), output)
      assert(output.contains(s"warning: could not record $Project as trusted in $copilot"), output)
      assert(output.endsWith("a b c "), output)
      assertEquals(Files.readString(claude), "{ not json")
    finally copilot.toFile.setReadable(true, true)
    assertEquals(Files.readString(copilot), """{"trustedFolders":["/Users/me/other"]}""")
    assertEquals(entries(copilot.getParent), Set("config.json"))

  test("a container run by hand, at /, records no project"):
    val (seed, home) = fixture()
    val (status, output) = run(seed, home, Path.of("/"))
    assertEquals(status, 0, output)
    val (claude, antigravity, copilot, codex) = trustFiles(home)
    Vector(claude, antigravity, copilot, codex).foreach(file => assert(!Files.exists(file), file.toString))
