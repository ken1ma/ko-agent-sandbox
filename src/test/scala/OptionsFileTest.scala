// The options file: its location and refusals, its syntax, the merge of its options under the
// command line's, what an action reads of it, and the startup lines naming it.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{Files, Path}

import AgentSandboxLauncher.{EgressCheckReads, EgressEffectiveReads, ResetReads}
import CommandLine.*
import HostCommands.Os

class OptionsFileTest extends munit.FunSuite:

  private val Shown = "~/.config/ko-agent-sandbox/options"
  private val FromFile = s" (from $Shown)"

  private def argument(line: String, env: Map[String, String] = Map.empty): Either[String, Option[String]] =
    OptionsFile.argumentOf(line, env.get)

  private def fileOptions(text: String, env: Map[String, String] = Map.empty): Either[String, ParsedCommandLine] =
    OptionsFile.options(text.getBytes(UTF_8), Shown, env.get)

  private def file(text: String): ParsedCommandLine = fileOptions(text).fold(fail(_), identity)

  private def commandLine(args: String*): ParsedCommandLine = parseArguments(args.toList).fold(fail(_), identity)

  /** The options in force with `text` as the file, and the startup lines it prints. */
  private def merged(text: String, args: String*): Either[String, (ParsedCommandLine, Vector[FileSupplied])] =
    merge(file(text), commandLine(args*))

  private def inForce(text: String, args: String*): ParsedCommandLine = merged(text, args*).fold(fail(_), _._1)

  test("a line holds one option: whitespace and comments around it go, a blank line or comment is nothing"):
    Vector("", "   ", "\t\r", "# a comment", "   # indented").foreach: line =>
      assertEquals(argument(line), Right(None), line)
    assertEquals(argument("  --memory = 8g  # the limit"), Right(Some("--memory=8g")))
    assertEquals(argument("\t--nesting=same-uid\r"), Right(Some("--nesting=same-uid")))
    assertEquals(argument("--memory=8g#inside a word"), Right(Some("--memory=8g")))
    assertEquals(argument("--env-aws-cred  # the host's AWS_PROFILE"), Right(Some("--env-aws-cred")))
    assertEquals(argument("--memory="), Right(Some("--memory=")))
    assertEquals(argument("--memory=   # none"), Right(Some("--memory=")))
    // The first = separates the name; whitespace inside the value is kept.
    assertEquals(argument("--env=NAME=VALUE"), Right(Some("--env=NAME=VALUE")))
    assertEquals(argument("--env=A=b c"), Right(Some("--env=A=b c")))
    assertEquals(file("--env=NAME=VALUE").env, Vector(EnvForward("NAME", Some("VALUE"))))
    assertEquals(file("--env-aws-cred").awsCredential, Some(AwsCredential.Request(None)))
    assert(argument("--memory 8g").swap.exists(_.contains("no =")), argument("--memory 8g").toString)
    assert(argument("\"--memory\"=8g").swap.exists(_.contains("never an option's name")))

  test("a quoted value keeps whitespace and #, takes three escapes, and nothing but a comment may follow it"):
    assertEquals(argument("--env=\"NAME=a #b\"  # c"), Right(Some("--env=NAME=a #b")))
    assertEquals(argument("--env=\"A=x\\\"y\\\\z\\$w\""), Right(Some("--env=A=x\"y\\z$w")))
    assertEquals(argument("--env=\"\""), Right(Some("--env=")))
    assert(argument("--env=\"A=\\n\"").swap.exists(_.contains("escapes")), argument("--env=\"A=\\n\"").toString)
    assert(argument("--env=\"A=\\").swap.exists(_.contains("escapes")))
    // Outside quotes every backslash is literal, so a Windows path needs none.
    assertEquals(argument("--claude-plugin-dir=C:\\mods\\band"), Right(Some("--claude-plugin-dir=C:\\mods\\band")))
    assert(argument("--env=NAME=\"a b\"").swap.exists(_.contains("unquoted value")))
    // The status line's line as doc/agent-settings.md spells it: a status-line placeholder is a
    // literal `${...}` to the file, not a variable of the launcher's.
    assertEquals(
      argument(
        "--env=\"KO_CLAUDE_STATUSLINE_FORMAT=\\${model.display_name} \\${effort.level} · context " +
          "\\${context_window.used_percentage.getOrElse(0)}%\"",
      ),
      Right(Some(
        "--env=KO_CLAUDE_STATUSLINE_FORMAT=${model.display_name} ${effort.level} · context " +
          "${context_window.used_percentage.getOrElse(0)}%",
      )),
    )
    assert(argument("--env=\"A=a\" b").swap.exists(_.contains("after the closing")))
    assert(argument("--env=\"A=a").swap.exists(_.contains("without its closing")))

  test("${NAME} expands once from the launcher's environment, quoted or not; a stray $ fails"):
    val env = Map("MEM" -> "8g", "名前" -> "v", "DIR" -> "x", "V" -> "${MEM}#\"\\", "EMPTY" -> "")
    assertEquals(argument("--memory=${MEM}", env), Right(Some("--memory=8g")))
    assertEquals(argument("--memory=\"${MEM}\"", env), Right(Some("--memory=8g")))
    assertEquals(argument("--env=A=${名前}", env), Right(Some("--env=A=v")))
    assertEquals(argument("--env=\"A=\\${MEM}\"", env), Right(Some("--env=A=${MEM}")))
    assertEquals(argument("--env=P=C:\\${DIR}", env), Right(Some("--env=P=C:\\x")))
    // A value is taken as it is: no second expansion, comment, quote or escape inside it.
    assertEquals(argument("--env=A=${V}", env), Right(Some("--env=A=${MEM}#\"\\")))
    assertEquals(argument("--env=\"A=${V}\"", env), Right(Some("--env=A=${MEM}#\"\\")))
    assertEquals(argument("--memory=${MISSING}", env), Left("${MISSING} is not set in the launcher's environment"))
    assertEquals(argument("--memory=\"${MISSING}\"", env), Left("${MISSING} is not set in the launcher's environment"))
    // A defined, empty variable leaves the value empty, which returns the option to its default.
    assertEquals(argument("--memory=${EMPTY}", env), Right(Some("--memory=")))
    assertEquals(fileOptions("--memory=${EMPTY}", env).map(_.memory), Right(Some("")))
    assertEquals(fileOptions("--memory=${EMPTY}", env).flatMap(merge(_, NoOptions)).map(_._1.memory), Right(None))
    Vector("--env=A=$MEM", "--env=\"A=$MEM\"", "--env=A=$", "--env=A=${MEM", "--env=\"A=${MEM\"", "--env=A=${}")
      .foreach: line =>
        assert(argument(line, env).isLeft, line)
    assert(argument("--env=A=$MEM", env).swap.exists(_.contains("\\$ in a quoted value")))
    assert(argument("--env=A=${MEM", env).swap.exists(_.contains("without its }")))
    // `#` starts a comment inside ${ too, outside quotes.
    assert(argument("--env=A=${X#}", Map("X#" -> "1")).swap.exists(_.contains("without its }")))
    // Option names are not expanded.
    assertEquals(argument("--${MEM}=1", env), Right(Some("--${MEM}=1")))

  test("each refusal names the file and its line"):
    assertEquals(
      OptionsFile.options(Array[Byte]('#', '\n', 0xc3.toByte, 0x28), Shown, Map.empty.get),
      Left(s"error: $Shown:2: not UTF-8"),
    )
    assertEquals(
      fileOptions("# options\n\n--env=\"A=a"),
      Left(s"error: $Shown:3: a quoted value without its closing \""),
    )
    assertEquals(
      fileOptions("claude"),
      Left(s"error: $Shown:1: claude is not an option; give a command on the command line"),
    )
    assertEquals(
      fileOptions("--memory=8g\n--"),
      Left(s"error: $Shown:2: -- ends the options on the command line; this file holds options alone"),
    )
    Vector("--help", "--reset", "--egress-check=pypi.org").foreach: action =>
      assertEquals(
        fileOptions(action),
        Left(s"error: $Shown:1: $action is a management action; give it on the command line"),
      )
    assertEquals(
      fileOptions("--frobnicate"),
      Left(s"error: $Shown:1: unknown option --frobnicate\nRun --help for the launcher actions."),
    )
    assertEquals(
      fileOptions("--no-options-file"),
      Left(s"error: $Shown:1: --no-options-file belongs on the command line, where it skips this file"),
    )
    assertEquals(fileOptions("--memory=1g\n# again\n--memory=2g"), Left(s"error: $Shown:3: --memory is given twice"))
    assertEquals(
      fileOptions("--nesting=on"),
      Left(s"error: $Shown:1: --nesting=on; the values are none, same-uid, exactly"),
    )
    assertEquals(
      fileOptions("--env=X\n--egress-cred=X@a.example").flatMap(merge(_, NoOptions)),
      Left("error: --env=X and --egress-cred=X@…; pass X to one of them"),
    )
    // An absent last newline and CRLF line ends are lines like any other.
    assertEquals(file("--memory=8g\r\n--nesting=same-uid").nesting, Some("same-uid"))

  test("--no-options-file skips the file for a launch or an action; after the command it is the command's"):
    assertEquals(commandLine("--no-options-file", "claude").noOptionsFile, true)
    assertEquals(commandLine("--no-options-file", "--reset").action, Some(("--reset", Nil)))
    assertEquals(commandLine("claude", "--no-options-file").command, List("claude", "--no-options-file"))
    assertEquals(commandLine("--", "--no-options-file").command, List("--no-options-file"))
    assertEquals(commandLine("claude", "--no-options-file").noOptionsFile, false)
    assert(parseArguments(List("--no-options-file", "--no-options-file")).swap.exists(_.contains("twice")))
    assert(parseArguments(List("--no-options-file=yes")).swap.exists(_.contains("takes no value")))
    val unread = OptionsFile.Loaded(Path.of("/unread"), file("--memory=8g"))
    def read: Either[String, Option[OptionsFile.Loaded]] = throw AssertionError("the options file was read")
    Vector(commandLine("--no-options-file", "claude"), commandLine("--no-options-file", "--reset")).foreach: skipping =>
      val options = OptionsFile.inForce(skipping, FileOptionNames.toSet)(read).fold(fail(_), identity)
      assertEquals((options.parsed.memory, options.supplied, options.file), (None, Vector.empty, None))
    val options = OptionsFile.inForce(commandLine("claude", "--no-options-file"), FileOptionNames.toSet)(
      Right(Some(unread)),
    ).fold(fail(_), identity)
    assertEquals(options.parsed.memory, Some("8g"))
    assertEquals(OptionsFile.inForce(NoOptions, Set.empty)(Left("error: unreadable")), Left("error: unreadable"))

  test("the file is under the configuration root of each OS, absolute and canonical, and never inside the workspace"):
    val base = Files.createTempDirectory("options-file").toRealPath()
    for os <- Vector(Os.Linux, Os.Mac) do
      assertEquals(
        OptionsFile.pathOf(os, Map("XDG_CONFIG_HOME" -> base.toString, "HOME" -> "/elsewhere").get),
        Right(base.resolve("ko-agent-sandbox/options")),
      )
      assertEquals(
        OptionsFile.pathOf(os, Map("XDG_CONFIG_HOME" -> "", "HOME" -> base.toString).get),
        Right(base.resolve(".config/ko-agent-sandbox/options")),
      )
    assertEquals(
      OptionsFile.pathOf(Os.Windows, Map("APPDATA" -> base.toString, "XDG_CONFIG_HOME" -> "/elsewhere").get),
      Right(base.resolve("ko-agent-sandbox").resolve("options")),
    )
    val relative = OptionsFile.pathOf(Os.Linux, Map("XDG_CONFIG_HOME" -> "config").get)
    assert(
      relative.swap.exists(reason => reason.contains("not an absolute path") && reason.contains("options file")),
      relative.toString,
    )
    assert(OptionsFile.pathOf(Os.Windows, Map("APPDATA" -> "config").get).isLeft)
    assertEquals(OptionsFile.pathOf(Os.Linux, Map.empty[String, String].get), Left("error: HOME is not set"))

    val workspace = Files.createDirectories(base.resolve("workspace"))
    val outside = Files.createDirectories(base.resolve("config/ko-agent-sandbox")).resolve("options")
    assertEquals(OptionsFile.refusal(Os.Linux, outside, workspace), None)
    val inside = workspace.resolve(".config/ko-agent-sandbox/options")
    assert(OptionsFile.refusal(Os.Linux, inside, workspace).exists(_.contains("inside the workspace root")))
    // A configuration root linked into the workspace is inside it, as pathOf resolves it.
    val linkTarget = Files.createDirectories(workspace.resolve("cfg"))
    val linked = Files.createSymbolicLink(base.resolve("linked-config"), linkTarget)
    val resolved = OptionsFile.pathOf(Os.Linux, Map("XDG_CONFIG_HOME" -> linked.toString).get).fold(fail(_), identity)
    assertEquals(resolved, workspace.resolve("cfg/ko-agent-sandbox/options"))
    // Refused once there is a file to read; with none, nothing chooses a grant.
    val linkedConfig = Map("XDG_CONFIG_HOME" -> linked.toString).get
    assertEquals(OptionsFile.load(Os.Linux, workspace, linkedConfig), Right(None))
    Files.createDirectories(resolved.getParent)
    Files.writeString(resolved, "--nesting=same-uid\n")
    assert(OptionsFile.load(Os.Linux, workspace, linkedConfig).swap.exists(_.contains("inside the workspace root")))

    // An absent file supplies nothing; a present one is parsed; one that cannot be read fails.
    val config = Map("XDG_CONFIG_HOME" -> base.resolve("config").toString).get
    assertEquals(OptionsFile.load(Os.Linux, workspace, config), Right(None))
    Files.writeString(outside, "--memory=8g\n")
    assertEquals(OptionsFile.load(Os.Linux, workspace, config).map(_.map(_.options.memory)), Right(Some(Some("8g"))))
    Files.delete(outside)
    Files.createDirectories(outside)
    assert(OptionsFile.load(Os.Linux, workspace, config).swap.exists(_.contains("cannot read")))

  test("every option the file holds has a value that returns it to its default for one launch"):
    val everything =
      """--workspace=read-only
        |--egress=deny-all
        |--clipboard=paste
        |--audio=mic
        |--nesting=same-uid
        |--session-start=immediate
        |--env-aws-cred=team
        |--run-on-host=sbt
        |--model-provider=aws
        |--persistent-volume=shared
        |--memory=8g
        |--image=sandbox:mine
        |--proxy-image=proxy:mine
        |--env=A=1
        |--egress-cred=X@a.example
        |--claude-plugin-dir=/mods/band""".stripMargin
    val defaults = Vector(
      "--workspace=live", "--egress=deny-unless-allowed", "--clipboard=off", "--audio=off", "--nesting=none",
      "--session-start=pause", "--env-aws-cred=", "--run-on-host=", "--model-provider=", "--persistent-volume=",
      "--memory=", "--image=", "--proxy-image=", "--env=", "--egress-cred=", "--claude-plugin-dir=",
    )
    // Each option the file can hold has its default value here.
    assertEquals(defaults.map(_.takeWhile(_ != '=')).toSet, FileOptionNames.toSet)
    val (reset, supplied) = merged(everything, defaults*).fold(fail(_), identity)
    assertEquals(supplied, Vector.empty)
    assertEquals(
      (reset.workspaceMode, reset.egressProfile, reset.clipboardMode, reset.microphone, reset.nestingMode),
      ("live", "deny-unless-allowed", "off", false, "none"),
    )
    assertEquals(reset.sessionStartMode, "pause")
    assertEquals(
      (reset.awsCredential, reset.runOnHost, reset.persistentVolume, reset.memory),
      (None, None, None, None),
    )
    assertEquals((reset.image, reset.proxyImage), (None, None))
    assertEquals(
      (reset.env, reset.credentialBindings, reset.claudePlugins, reset.modelProviders),
      (Vector.empty, Vector.empty, Vector.empty, Vector.empty),
    )
    // --env-aws-cred alone keeps reading AWS_PROFILE.
    assertEquals(inForce("--env-aws-cred=team", "--env-aws-cred").awsCredential, Some(AwsCredential.Request(None)))
    // A repeatable option's empty value drops the file's entries; the entries after it still add.
    assertEquals(inForce("--env=A\n--env=B", "--env=", "--env=FOO").env, Vector(EnvForward("FOO", None)))
    // A closed choice keeps refusing an empty value, which an unset variable in a script produces.
    Vector("--workspace", "--egress", "--clipboard", "--audio", "--nesting", "--session-start").foreach: option =>
      assert(parseArguments(List(s"$option=")).isLeft, option)
      assert(fileOptions(s"$option=").swap.exists(_.startsWith(s"error: $Shown:1: ")), option)

  test("the command line's options replace the file's, repeatable ones merged by name or directory"):
    assertEquals(inForce("--memory=8g", "--memory=4g").memory, Some("4g"))
    assertEquals(inForce("--memory=8g", "claude").memory, Some("8g"))
    assertEquals(inForce("--run-on-host=sbt,mill", "--run-on-host=gradle").runOnHost, Some(Vector("gradle")))
    assertEquals(
      inForce("--env=A=1\n--env=B=2", "--env=B=3").env,
      Vector(EnvForward("A", Some("1")), EnvForward("B", Some("3"))),
    )
    assertEquals(
      inForce("--egress-cred=X@a.example\n--egress-cred=Y@a.example", "--egress-cred=X@b.example")
        .credentialBindings.map(_.spelled),
      Vector("Y@a.example:Authorization", "X@b.example:Authorization"),
    )
    assertEquals(
      inForce("--claude-plugin-dir=/a\n--claude-plugin-dir=/b", "--claude-plugin-dir=/b", "--claude-plugin-dir=/c")
        .claudePlugins,
      Vector("/a", "/b", "/c"),
    )
    // The command line's --model-provider adds to the file's names; its empty value drops them.
    val fileProviders = "--model-provider=anthropic,openai"
    assertEquals(
      inForce(fileProviders, "--model-provider=google").modelProviders,
      Vector("anthropic", "openai", "google"),
    )
    assertEquals(inForce(fileProviders, "--model-provider=openai").modelProviders, Vector("anthropic", "openai"))
    assertEquals(
      inForce(fileProviders, "--model-provider=", "--model-provider=google").modelProviders,
      Vector("google"),
    )
    // The checks across options run on the merged set, whichever source each option comes from.
    assertEquals(
      merged("--env=X", "--egress-cred=X@a.example").map(_._1),
      Left("error: --env=X and --egress-cred=X@…; pass X to one of them"),
    )
    assert(merged("--env=X\n--egress-cred=X@a.example", "--env=").isRight)
    assert(merged("--env-aws-cred", "--env=AWS_SESSION_TOKEN").swap.exists(_.contains("forwards AWS_SESSION_TOKEN")))
    // The action, the command and --no-options-file are the command line's alone.
    assertEquals(inForce("--memory=8g", "--reset", "x").action, Some(("--reset", List("x"))))

  test("the file's options are printed once, each naming the file, an --env by its name alone"):
    val (parsed, supplied) =
      merged("--memory=8g\n--env=SECRET=hunter2\n--nesting=same-uid\n--image=i", "--image=j").fold(fail(_), identity)
    val options = OptionsInForce(parsed, supplied, Some(Path.of("/home/me/.config/ko-agent-sandbox/options")))
    def lines(color: Boolean) =
      options.fileLines(Set("--nesting"), Os.Linux, color).map(_.replace("/home/me/.config", "~/.config"))
    assertEquals(lines(color = false), Vector(s"--memory=8g$FromFile", s"--env=SECRET$FromFile"))
    // The value is what the user chose, and the source is there to look up, parentheses included.
    val (chosen, gray, off) = ("\u001b[38;5;207m", "\u001b[38;5;245m", "\u001b[0m")
    val source = s" $gray(from $Shown)$off"
    assertEquals(
      lines(color = true),
      Vector(s"--memory=${chosen}8g$off$source", s"--env=${chosen}SECRET$off$source"),
    )
    assert(!options.fileLines(os = Os.Linux, color = false).exists(_.contains("hunter2")))
    assertEquals(options.from("--nesting", Os.Linux, color = false).replace("/home/me/.config", "~/.config"), FromFile)
    assertEquals(options.from("--image", Os.Linux, color = false), "")
    // The egress line credits the file with its own provider names alone.
    val (withProviders, providersSupplied) =
      merged("--model-provider=anthropic,openai", "--model-provider=google").fold(fail(_), identity)
    def providersFrom(selected: String*): String =
      OptionsInForce(withProviders, providersSupplied, Some(Path.of("/home/me/.config/ko-agent-sandbox/options")))
        .providersFrom(selected.toVector, Os.Linux, color = false).replace("/home/me/.config", "~/.config")
    assertEquals(providersFrom("anthropic", "openai"), FromFile)
    assertEquals(providersFrom("anthropic", "openai", "google"), s" (anthropic, openai from $Shown)")
    assertEquals(OptionsInForce(parsed, Vector.empty, None).fileLines(color = false), Vector.empty)
    assertEquals(
      LaunchMessages.sharedVolumeLine("team", FromFile, color = false),
      s"agent state: volume team, shared by --persistent-volume=team$FromFile",
    )
    assertEquals(
      LaunchMessages.sharedVolumeLine("team", color = false),
      "agent state: volume team, shared by --persistent-volume=team",
    )

  test("an action reads the file's options that configure it and ignores the rest"):
    val text =
      """--persistent-volume=shared
        |--egress=deny-all
        |--model-provider=openai
        |--egress-cred=X@a.example
        |--proxy-image=proxy:mine
        |--memory=8g
        |--env=X""".stripMargin
    def read(used: Set[String], args: String*): OptionsInForce =
      OptionsFile.inForce(commandLine(args*), used)(Right(Some(OptionsFile.Loaded(Path.of("/f"), file(text)))))
        .fold(fail(_), identity)
    val reset = read(ResetReads, "--reset")
    assertEquals(reset.parsed.persistentVolume, Some("shared"))
    assertEquals(reset.supplied.map(_.option), Vector("--persistent-volume"))
    // The file's --env and --egress-cred of one name meet only where both are read.
    val effective = read(EgressEffectiveReads, "--egress-effective")
    assertEquals(
      (effective.parsed.egress, effective.parsed.modelProviders, effective.parsed.proxyImage),
      (Some("deny-all"), Vector("openai"), Some("proxy:mine")),
    )
    assertEquals(effective.parsed.credentialBindings.map(_.name), Vector("X"))
    assertEquals(
      (effective.parsed.memory, effective.parsed.env, effective.parsed.persistentVolume),
      (None, Vector.empty, None),
    )
    val check = read(EgressCheckReads, "--egress-check=pypi.org")
    assertEquals((check.parsed.egress, check.parsed.proxyImage), (Some("deny-all"), Some("proxy:mine")))
    assertEquals(check.parsed.credentialBindings, Vector.empty)
    assertEquals(check.supplied.map(_.option).toSet, Set("--egress", "--model-provider", "--proxy-image"))
    // The command line's options replace the file's for an action too.
    assertEquals(
      read(EgressCheckReads, "--egress=deny-unless-model", "--egress-check=x").parsed.egress,
      Some("deny-unless-model"),
    )
