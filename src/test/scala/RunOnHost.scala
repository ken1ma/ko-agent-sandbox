// The gate's wrapper driver, EmitRunOnHostProfile's sibling: the RunOnHostSandbox wrapper with the authority file
// as an argument, where the durable front-end — the launcher's --run-command-on-host action, behind
// the channel — reads the bundled copy. src/probe/run-on-host-profile-gate.sh is its caller.
//
//   java -cp <the classpath EmitRunOnHostProfile prints> \
//     agentsandbox.launcher.RunOnHost <program> <project> [authority-file] -- <args...>
//
// Plain java, never `sbt Test/runMain`: runMain would host this in the build's own JVM, whose
// server holds the target project's portfile — the one-server-per-project refusal — and whose exit is sys.exit's.
// Exits with the command's code; a refusal is 2, on stderr.

package agentsandbox.launcher

import java.nio.file.Paths

import RunOnHostPrereqs.Program

object RunOnHost:

  def main(args: Array[String]): Unit =
    val (front, commandArgs) = args.toList.span(_ != "--") match
      case (before, "--" :: rest) => (before, rest)
      case (before, _)            => (before, Nil)

    val usage =
      s"usage: RunOnHost <${Program.values.map(_.name).mkString("|")}> <project> [authority-file] -- <args...>"
    front match
      case programName :: projectName :: rest if rest.sizeIs <= 1 =>
        val program = Program.values.find(_.name == programName.toLowerCase).getOrElse:
          Console.err.println(s"unknown program $programName\n$usage")
          sys.exit(2)
        val runtime = RunOnHostSandbox.readRuntimeAuthority(rest.headOption.map(Paths.get(_)))
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        sys.exit(
          RunOnHostSandbox.run(Paths.get(projectName), program, commandArgs, runtime, uid, Console.err.println),
        )
      case _ =>
        Console.err.println(usage)
        sys.exit(2)
