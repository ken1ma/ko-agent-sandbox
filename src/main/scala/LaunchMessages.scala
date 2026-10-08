// What a launch tells the user and the agent about the session's options: the stderr lines naming
// a boundary the options weaken, and the section appended to the image's agent instructions.

package agentsandbox.launcher

import agentsandbox.egress.CredentialBinding
import agentsandbox.egress.LogHelper.sha256Hex

import AgentSandboxLauncher.*
import HostCommands.*

object LaunchMessages:

  /** The launch's host-command lines: the programs chosen — authority a container session alone
    * does not have, so tinted as a weakened boundary (HostCommands.weakened) — and what
    * running them on the host costs the user; under `--write=reject` an extra line, tinted alike
    * as a boundary weaker than the option says, since a host command writes the project as its
    * program does while the session's own writes are refused (SECURITY.md "Run on host"). */
  def runOnHostLines(runOnHost: Seq[String], writeMode: String, color: Boolean = colorStderr): Vector[String] =
    val programs = weakened(s"ko-sandbox-run-on-host: ${runOnHost.mkString(", ")} on host", color)
    val displaced = runOnHost.collect:
      case "sbt" => "sbt server"
      case "mill" => "mill daemon"
    val shutdown = Option.when(displaced.nonEmpty)(
      s"your own ${displaced.mkString(" or ")} in the build directory is stopped when the agent runs that program",
    )
    val reject = Option.when(writeMode == "reject")(
      weakened(
        "run on host: --write=reject refuses the session's own writes, not a host command's: a build writes the" +
          " project as its program does",
        color,
      ),
    )
    Vector(programs) ++ shutdown ++ reject

  def nestingLine(mode: String, color: Boolean = colorStderr): String =
    weakened(
      s"nested containers: $mode by $NestingVariable; /proc unmasked, SELinux label " +
        "disabled and CAP_SYS_CHROOT added, for the whole session",
      color,
    )

  def clipboardLine(mode: String, color: Boolean = colorStderr): String =
    weakened(
      s"clipboard: $mode by $ClipboardVariable; the agent can read an image you copy" +
        (if mode == "bidirectional" then " and set your clipboard" else ""),
      color,
    )

  /** One widening report per program whose rule file names hosts, each a grant beyond the
    * program's Maven Central host (RunOnHostPrereqs.egressRuleText). The launch reads the files for
    * this report and the bindings' check (EgressCredentials.checkHosts): the runner reads them again
    * at a program's first command, where a refusal reaches the agent and not the user. */
  def runOnHostWideningLines(
    programHosts: Seq[(String, Vector[String])],
    color: Boolean = colorStderr,
  ): Vector[String] =
    programHosts.toVector.flatMap:
      case (program, hosts) if hosts.nonEmpty =>
        val grants = hosts.map(host => shown(RunOnHostPrereqs.programRuleLine(host)))
        val file = s".ko-agent-sandbox/run-on-host/$program/egress/rule"
        wideningReport(s"run-on-host egress rules ($file)", grants, color)
      case _ => Vector.empty

  /**
   * The section appended to the image's agent instructions, telling the agent what to do under
   * this session's options rather than leaving it to be inferred from failing
   * commands. Directive by design: it says what to do, never how to probe. It states the *grant*
   * vocabulary and the proxy owns that: an agent told a grant word the proxy does not define writes
   * a rule file that fails the next launch with "which is no grant", which is a confusing way to
   * learn that these instructions drifted. AgentSandboxLauncherTest holds the
   * instruction vocabulary to the proxy source.
   */
  def appendedSection(
    /** Where the container has the project (SandboxProject.mountPathOf): the one place the
      * instructions name it, since the image's own text says "the project directory". */
    mountPath: String,
    writeMode: String,
    resolved: String,
    runOnHost: Vector[String] = Vector.empty,
    // Whether this host could serve --run-on-host at all (macOS): decides the discovery line
    // (doc/run-on-host.md, "The channel and the command"). Constant per machine, so the agents.md
    // stamp needs no part of it.
    hostCommandsAvailable: Boolean = false,
    // What git cannot do in this session, in the container's words (SandboxProject.noGitInstruction
    // and readOnlyGitInstruction): the agent hears it before its first command.
    git: Option[String] = None,
    // The --egress-cred bindings: the variables holding a placeholder, and where the proxy substitutes it.
    brokered: Vector[CredentialBinding] = Vector.empty,
  ): String =
    val profileLine = resolved.linesIterator.next()
    val workspace = writeMode match
      // The plain reject instruction would be false under --run-on-host: a host command writes the
      // project (SECURITY.md "Run on host", the --write=reject composition).
      case "reject" if runOnHost.nonEmpty =>
        s"""`$mountPath` is read-only to this session's own writes; only commands through
          |`ko-sandbox-run-on-host` write the project, on the host. For anything a command does not
          |write, use `~` or `/tmp` for temporary work and return results in the conversation.
          |Tell the user to relaunch with `--write=live` when project files must be written.""".stripMargin
      case "reject" =>
        s"""`$mountPath` is read-only this session. Do not attempt writes there; use `~` or `/tmp`
          |for temporary work and return results in the conversation. Tell the user to relaunch
          |with `--write=live` when project files must be written.""".stripMargin
      case "live" =>
        s"""`$mountPath` is writable and shared live with the host project directory through the
          |`ko-agent-fs` filter. Git config, hooks, `.git` files, `commondir`, `gitdir`, rebase, bisect
          |and rerere state, alternates, `.ko-agent-sandbox` and what `$$KO_AGENT_SANDBOX_FILE_RULES`
          |makes read-only cannot be modified at any depth; in those rules the last line naming an
          |entry or an ancestor decides. Symlink targets must be relative and remain inside the
          |workspace.""".stripMargin
      case _ =>
        throw IllegalArgumentException(s"unknown write mode: $writeMode")
    val gitParagraph = git.fold("")(paragraph => s"\n\n$paragraph")
    val runOnHostSection =
      if runOnHost.nonEmpty then
        val names = runOnHost.mkString(", ")
        val commands = runOnHost.map(program => s"`ko-sandbox-run-on-host $program …`").mkString(" or ")
        // Each sentence below names only the programs this session serves: the channel refuses the others.
        def selected(programs: String*): Vector[String] = programs.filter(runOnHost.contains).toVector
        def listed(programs: Vector[String]): String = programs match
          case Vector(one)     => one
          case init :+ last    => s"${init.mkString(", ")} and $last"
          case _               => ""
        val withDaemon = selected("sbt", "mill", "gradle")
        val daemons = withDaemon match
          case Vector()    => ""
          case Vector(one) => s"\nThe daemon of $one stays warm across invocations."
          case many        => s"\nThe daemons of ${listed(many)} stay warm across invocations."
        val sbtUsage =
          if runOnHost.contains("sbt") then
            """ To run several
              |commands in one, quote them: `ko-sandbox-run-on-host sbt 'compile; test'`; sbt reads separate
              |arguments as one command, and `compile test` fails to parse. The container's own `sbt` is the last
              |resort, not an alternative: by default its output is outside the project and discarded
              |with the session, so it compiles everything once per session, while the host keeps its
              |build between sessions.""".stripMargin
          else ""
        val noListener = selected("sbt", "mvn")
        val listenerDenied =
          if noListener.isEmpty then ""
          else
            s""" Under ${listed(noListener)} the host grants no
               |TCP listener, so a test that binds one fails there with `Operation not permitted`; that
               |suite alone runs in the container.""".stripMargin
        val withListener = selected("mill", "gradle")
        val listenerGranted =
          if withListener.isEmpty then ""
          else s" Under ${listed(withListener)} a build's processes can bind listeners."
        s"""
           |## Run on host
           |
           |Run $names for this project as $commands: they run on the
           |host, sandboxed to the project, per-project run-on-host caches and configured artifact repositories,
           |and they may write the project except `.git`, `.ko-agent-sandbox` and what
           |`$$KO_AGENT_SANDBOX_FILE_RULES` makes read-only.$daemons$sbtUsage$listenerDenied$listenerGranted
           |Any other host command that fails or is refused is reported to the user,
           |never re-run in the container.
           |The environment variable `${RunOnHostChannel.RunOnHostVariable}` holds this program list.
           |""".stripMargin
      else if hostCommandsAvailable then
        s"""
           |## Run on host
           |
           |`ko-sandbox-run-on-host` is absent from this session. If sbt, `mill`, Gradle or Maven
           |builds here are slow, or the machine is short on memory, tell the user: relaunching with
           |`--run-on-host=sbt,mill,gradle,mvn` runs them on the host — memory reclaimed on exit
           |rather than left with the podman machine, and at host speed.
           |""".stripMargin
      else ""
    val refused =
      """If a package registry or clone host you need is not allowed, do not look for another
        |route: name the host to the user, who adds `allow https://<host>/ read` to
        |`.ko-agent-sandbox/egress/rule` on the host and relaunches — under the default
        |deny-unless-allowed profile, if this session's profile ignores the file's allow
        |lines.""".stripMargin
    s"""
       |
       |# What this session may do
       |
       |$workspace$gitParagraph
       |$runOnHostSection
       |## Egress
       |
       |$profileLine
       |
       |For a destination's grants and restrictions, consult `$$KO_AGENT_SANDBOX_EGRESS_RULESET`.
       |Anything not allowed by the ruleset is refused. A line grants exactly its words under its
       |path: `tunnel` is an opaque tunnel; `read` is GET and HEAD, bodyless; `git-fetch`
       |serves `clone` and `pull`; `method=` names the
       |HTTP methods allowed there. On an inspected host, the rule with the longest matching
       |path decides which operations are permitted. A rule path ending in `/` matches request
       |paths with that prefix; other rule paths match exactly. A request matching no rule is
       |refused. For rules below `/`, a request path is also refused unless it is printable ASCII
       |with `%` escaping only non-ASCII text or a space, and has no dot segment, backslash, `;`,
       |`#` or empty segment; a `POST`, `PUT`, `PATCH` or `DELETE` path may carry no `%` or dot
       |segment under any rule.
       |
       |$refused
       |${brokeredParagraph(brokered)}""".stripMargin

  /** The agent's paragraph for a launch with bindings: a 401 from another host or place is the placeholder
    * sent, not a wrong token. */
  def brokeredParagraph(brokered: Vector[CredentialBinding]): String =
    if brokered.isEmpty then ""
    else
      val bindings = brokered.map: binding =>
        s"`${binding.name}` (${binding.target}, ${binding.place.shown})"
      s"""
         |${bindings.mkString(", ")} ${if bindings.size == 1 then "holds a placeholder" else "hold placeholders"}
         |the proxy replaces with the real value only in the bound header or parameter on the bound host;
         |a 401 from any other host or place means the placeholder was sent, not that the token is wrong.
         |""".stripMargin

  def agentDocumentStamp(
    imageId: String,
    writeMode: String,
    rulesetText: String,
    runOnHost: Vector[String] = Vector.empty,
    git: Option[String] = None,
    brokered: Vector[CredentialBinding] = Vector.empty,
  ): String =
    s"$imageId $writeMode ${sha256Hex(rulesetText)}"
      + (if runOnHost.isEmpty then "" else s" ${runOnHost.mkString(",")}")
      + git.fold("")(paragraph => s" git:${sha256Hex(paragraph)}")
      + (if brokered.isEmpty then "" else s" brokered:${brokered.map(_.spelled).mkString(",")}")
