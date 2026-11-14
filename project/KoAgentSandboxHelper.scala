// Refuses a task or command in a ko-agent-sandbox launch's run-on-host sbt server (doc/run-on-host.md, "Telling a
// host command apart in a build"). Copy this file into another build's project/ directory as it is; build.sbt then
// changes only where it wraps a task or a command:
//
//     dist := KoAgentSandboxHelper.outsideHostCommand("dist", KoAgentSandboxHelper.BuildsWhatYouRun)(
//       Def.task(Def.uncached(assembly.value)),
//     ).value
//
//     commands += Command.command("integrationTest") { state =>
//       KoAgentSandboxHelper.outsideHostCommand(state, "integrationTest", "whose confinement starts no container") {
//         ...
//       }
//     }
//
// - The file is in Scala 2 syntax, so that sbt 1.x, which compiles project/ with Scala 2.12, compiles it as sbt 2.x
//   does (measured with sbt 1.11.7 and 2.0.12). Def.uncached is sbt 2's: under sbt 1.x, the example's task is
//   Def.task(assembly.value).
// - Every run-on-host command's environment holds KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND=1. Under sbt the build runs
//   in the server, so the variable marks the server, whichever client sent the command.
// - A terminal's `sbt` attaches to the launch's server while that server holds the portfile, so the refusal also
//   reaches a person at a terminal. It names `sbt shutdown` as the next step.

import sbt.*

object KoAgentSandboxHelper {

  val HostCommandVariable = "KO_AGENT_SANDBOX_RUN_ON_HOST_COMMAND"

  /** Whether this JVM runs a host command: under sbt, whether this server is a launch's. */
  def inHostCommand: Boolean = sys.env.get(HostCommandVariable).contains("1")

  /** The reason for a task that builds what a person runs outside the sandbox (SECURITY.md, "Cache poisoning stops
    * at the workspace"). */
  val BuildsWhatYouRun = "whose caches the agent's commands write, and the result runs outside the sandbox"

  def refusal(name: String, reason: String): String =
    s"$name: this sbt server is a ko-agent-sandbox launch's run-on-host server, $reason. In a terminal on the host, " +
      s"run `sbt shutdown`, then `sbt $name` again."

  /** The task, or its refusal in a host command. The refusal comes before any of the task's dependencies run, so a
    * refused build leaves no output behind. */
  def outsideHostCommand[A](name: String, reason: String)(task: Def.Initialize[Task[A]]): Def.Initialize[Task[A]] =
    Def.ifS(Def.task(inHostCommand))(Def.task[A](throw new MessageOnlyException(refusal(name, reason))))(task)

  /** The command's next state, or its refusal in a host command. */
  def outsideHostCommand(state: State, name: String, reason: String)(run: => State): State =
    if (inHostCommand) {
      state.log.error(refusal(name, reason))
      state.fail
    } else run
}
