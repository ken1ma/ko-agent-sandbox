// The launcher's side of the file rules: the grammar and its refusals, the defaults, the project's
// file as read, and the text the filter exchanges.

package agentsandbox.launcher

import java.nio.file.Files

import FileRules.*

class FileRulesTest extends munit.FunSuite:

  private def lines(text: String): Vector[Line] =
    parse(text, "rule").fold(why => fail(why), identity)

  private def refused(text: String, token: String)(using munit.Location): Unit =
    parse(text, "rule") match
      case Right(parsed) => fail(s"$text was accepted as $parsed")
      case Left(why)     => assert(why.contains(token), why)

  test("a line is a word and a name, comments and blank lines as in egress/rule"):
    assertEquals(
      lines("# editor\nreadonly .vscode   # tasks\n\nwritable .vscode/settings.json\nreadonly *.code-workspace\n"),
      Vector(
        Line(Word.ReadOnly, ".vscode"),
        Line(Word.Writable, ".vscode/settings.json"),
        Line(Word.ReadOnly, "*.code-workspace"),
      ),
    )

  test("every ambiguity refuses, saying what a line may hold"):
    refused("allow .vscode\n", "not a word")
    refused("readonly\n", "one word and one name")
    refused("readonly .vscode .idea\n", "one word and one name")
    refused("readonly /.vscode\n", "leading, trailing or doubled")
    refused("readonly .vscode/\n", "leading, trailing or doubled")
    refused("readonly a//b\n", "leading, trailing or doubled")
    refused("readonly ../x\n", "`.` or `..`")
    refused("readonly ./x\n", "`.` or `..`")
    refused("readonly .VSCode\n", "lowercase")
    refused("readonly .vs#code\n", "only a-z")
    refused("readonly naïve\n", "only a-z")
    refused("readonly [ab]\n", "only a-z")
    refused("writable .git/hooks\n", "`.git` is the filter's own")
    refused("readonly apps/.ko-agent-sandbox\n", "`.ko-agent-sandbox` is the filter's own")

  test("the defaults parse, protect the agents' and editors' files, and end with the dependency directory"):
    val names = Defaults.map(_.name)
    Vector(
      ".claude/settings.json", ".mcp.json", ".codex/config.toml", ".gemini/settings.json", ".github/hooks",
      ".agents/hooks.json", ".kiro/hooks", ".opencode", ".husky", ".pre-commit-config.yaml", ".vscode",
      ".idea", ".devcontainer", "mise.toml", ".tool-versions", ".miserc.toml",
    ).foreach(name => assert(names.contains(name), name))
    assertEquals(Defaults.last, Line(Word.Writable, "node_modules"))
    assertEquals(Defaults.count(_.word == Word.Writable), 1)
    // What a model reads and no host program runs stays writable.
    Vector("CLAUDE.md", "AGENTS.md", ".cursor/rules", ".agents/skills", ".envrc")
      .foreach(name => assert(!names.contains(name), name))

  test("a session gets the defaults, then the project's lines, and the launch names every writable line"):
    val written = lines("writable .claude/skills\nwritable .vscode/settings.json\n")
    assertEquals(resolve(written), Defaults ++ written)
    val project = Some(("writable .claude/skills\nwritable .vscode/settings.json", written))
    assertEquals(
      launchLines(project, color = false),
      Vector(
        "file rules (.ko-agent-sandbox/file/rule): writable .claude/skills; writable .vscode/settings.json",
        "file rules widen:",
        "  writable .claude/skills",
        "  writable .vscode/settings.json",
      ),
    )
    assertEquals(
      launchLines(None, color = false),
      Vector("file rules: no project rule file; the launcher-owned defaults"),
    )

  test("a joined mount's rules are described beyond the defaults, and read back from the daemon's text"):
    val extra = lines("writable .claude/skills\nreadonly .envrc\n")
    val text = daemonText(Defaults ++ extra, Vector("/"))
    assertEquals(parseDaemonText(text), Right(Defaults ++ extra))
    assertEquals(
      runningLaunchLines(Defaults ++ extra, color = false),
      Vector(
        "file rules (the running mount's): writable .claude/skills; readonly .envrc",
        "file rules widen:",
        "  writable .claude/skills",
      ),
    )
    assertEquals(
      runningLaunchLines(Defaults, color = false),
      Vector("file rules (the running mount's): the launcher-owned defaults"),
    )
    // A mount a launcher of other defaults started is described whole.
    val otherDefaults = lines("readonly .vscode\n")
    assertEquals(
      runningLaunchLines(otherDefaults, color = false),
      Vector("file rules (the running mount's): readonly .vscode"),
    )
    assert(parseDaemonText("host-view /\nallow .vscode\n").swap.exists(_.contains("allow .vscode")))

  test("a command without a launch's set reads the project's lines, and a launch's set reads back from its file"):
    val dir = Files.createTempDirectory("file-rules-project")
    try
      assertEquals(ofProject(dir), Right(Resolved(Defaults, Vector.empty, Vector.empty)))
      Files.createDirectories(dir.resolve(".ko-agent-sandbox/file"))
      Files.writeString(dir.resolve(".ko-agent-sandbox/file/rule"), "readonly .envrc\n")
      assertEquals(ofProject(dir).map(_.lines.last), Right(Line(Word.ReadOnly, ".envrc")))
      val resolved = Resolved(Vector(Line(Word.ReadOnly, ".vscode")), Vector(".husky/_"), Vector("tools"))
      val file = dir.resolve("file-rules.resolved")
      Files.writeString(file, resolved.text)
      assertEquals(readResolved(file), Right(resolved))
      assert(readResolved(dir.resolve("absent")).swap.exists(_.contains("cannot read the file rules")))
    finally FileHelper.deleteRecursively(dir)

  test("the project's file is read under the boundary directory's refusals"):
    val dir = Files.createTempDirectory("file-rules-test")
    try
      val fileDir = dir.resolve("file")
      assertEquals(readRuleFile(fileDir), Right(None))
      Files.createDirectories(fileDir)
      Files.writeString(fileDir.resolve("rule"), "readonly .envrc\n")
      assertEquals(readRuleFile(fileDir), Right(Some(("readonly .envrc", Vector(Line(Word.ReadOnly, ".envrc"))))))
      Files.writeString(fileDir.resolve("rule"), "# nothing yet\n")
      assert(readRuleFile(fileDir).swap.exists(_.contains("lists no lines")))
      Files.writeString(fileDir.resolve("rule"), "readonly .Envrc\n")
      assert(readRuleFile(fileDir).swap.exists(_.contains(".ko-agent-sandbox/file/rule")))
      Files.writeString(fileDir.resolve("rule"), "readonly .envrc\n")
      Files.writeString(fileDir.resolve("rules"), "readonly .envrc\n")
      assert(readRuleFile(fileDir).swap.exists(_.contains("not a rule file")))
    finally FileHelper.deleteRecursively(dir)

  test("the daemon's text leads with the host view, and the resolved set reads back"):
    assertEquals(
      daemonText(Vector(Line(Word.ReadOnly, ".vscode")), hostView(HostCommands.Os.Mac, "/Users/u/p")),
      "host-view /Users /private /var/folders\nreadonly .vscode\n",
    )
    assertEquals(hostView(HostCommands.Os.Linux, "/home/u/p"), Vector("/"))
    assertEquals(hostView(HostCommands.Os.Windows, "/mnt/d/src/p"), Vector("/mnt/d"))
    val resolved = Resolved(
      Vector(Line(Word.Writable, "node_modules")),
      Vector(".husky/_"),
      Vector("tools"),
      Vector("shared/claude" -> "settings.json"),
    )
    assertEquals(parseResolved(resolved.text), Right(resolved))
    assertEquals(
      guardLines(resolved),
      Vector("file rules: read-only by the filter's guard: .husky/_, shared/claude/settings.json"),
    )

  test("every file rule example is a complete rule file the launcher accepts"):
    val root = java.nio.file.Paths.get("doc/file-rule-example")
    val examples = FileHelper.directoryEntries(root).filter(Files.isDirectory(_)).sortBy(_.getFileName.toString)
    assert(examples.nonEmpty, "no file rule examples found")
    examples.foreach: directory =>
      val names = FileHelper.directoryEntries(directory).map(_.getFileName.toString)
      assertEquals(names, Vector("rule"), directory.toString)
      assert(readRuleFile(directory).exists(_.nonEmpty), directory.toString)
