// Refuses a task or command in a ko-agent-sandbox launch's run-on-host sbt server (doc/run-on-host.md, "Telling a
// host command apart in a build"). Copy this file into another build's project/ directory as it is; build.sbt then
// changes only where it wraps a task or a command:
//
//     dist := KoAgentSandboxHelper.outsideHostCommand("dist", KoAgentSandboxHelper.BuildsWhatYouRun)(
//       Def.task(Def.uncached(assembly.value)),
//     ).value
//
//     commands += Command.command("integrationTest") { state =>
//       KoAgentSandboxHelper.outsideHostCommand(state, "integrationTest", "cannot start containers") {
//         ...
//       }
//     }
//
// - The file is in Scala 2 syntax, so that sbt 1.x, which compiles project/ with Scala 2.12, compiles it as sbt 2.x
//   does (measured with sbt 1.11.7 and 2.0.12). Def.uncached is sbt 2's: under sbt 1.x, the example's task is
//   Def.task(assembly.value).
// - Every run-on-host command's environment holds KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND=1. Under sbt the build runs
//   in the server, so the variable marks the server, whichever client sent the command.
// - A terminal's thin client attaches to the launch's server while that server holds the portfile, so the refusal
//   also reaches a person at a terminal: sbt 2's `sbt`, or sbt 1's `sbt --client`. sbt 1's plain `sbt` runs a JVM of
//   its own and never meets the launch's server (measured with sbt 1.13.1).
// - The refusal then ends the server, so that the person's next `sbt` starts a server of its own; the launch starts
//   another for its next host command.

import sbt.*

object KoAgentSandboxHelper {

  val HostCommandVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND"

  /** Whether this JVM runs a host command: under sbt, whether this server is a launch's. */
  def inHostCommand: Boolean = sys.env.get(HostCommandVariable).contains("1")

  /** The reason for a task that builds what a person runs outside the sandbox (SECURITY.md, "Cache poisoning stops
    * at the workspace"). */
  val BuildsWhatYouRun =
    "builds from caches that the agent's commands can write, while you run the result outside the sandbox"

  /** `reason` completes "…run-on-host started, which": what the server does that refuses the task. */
  def refusal(name: String, reason: String): String =
    s"$name: your sbt command reached an sbt server that ko-agent-sandbox's run-on-host started, which $reason. " +
      "Stopping that server: run your sbt command again in a host terminal."

  /** Ends this server shortly after the refusal. A failing task cannot queue sbt's `shutdown`, so the JVM exits, and
    * sbt's shutdown hook deletes the portfile (sbt 1.13.1 and 2.0.12). The delay lets the refused command's failure
    * reach its client first. */
  private def scheduleServerEnd(): Unit = {
    val exit = new Thread(new Runnable {
      def run(): Unit = { Thread.sleep(1000); System.exit(0) }
    }, "ko-agent-sandbox-refusal-exit")
    exit.setDaemon(true)
    exit.start()
  }

  /** The task, or its refusal in a host command. The refusal comes before any of the task's dependencies run, so a
    * refused build leaves no output behind. */
  def outsideHostCommand[A](name: String, reason: String)(task: Def.Initialize[Task[A]]): Def.Initialize[Task[A]] =
    Def.ifS(Def.task(inHostCommand))(Def.task[A] {
      // sbt reports a failed task only after every task of the command has finished (EvaluateTask.runTask), and the
      // server's end does not wait for that: in `all dist Compile/compile`, a compile that outlasts the delay would
      // take the report with it. So the refusal is logged the moment this task runs, and the failure only repeats
      // its gist.
      scheduleServerEnd()
      Keys.state.value.log.error(refusal(name, reason))
      // sbt prints the failure as "(dist) <message>", so the message does not name the task again.
      throw new MessageOnlyException("refused in a ko-agent-sandbox run-on-host sbt server")
    })(task)

  /** The command's next state, or its refusal in a host command. */
  def outsideHostCommand(state: State, name: String, reason: String)(run: => State): State =
    if (inHostCommand) {
      scheduleServerEnd()
      state.log.error(refusal(name, reason))
      state.fail
    } else run
}
