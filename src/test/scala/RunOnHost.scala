// The gate's wrapper driver, EmitBuildProfile's sibling: the RunOnHostSandbox wrapper with the authority file
// as an argument, where the durable front-end — the launcher's --run-build-on-host verb, behind
// the channel — reads the bundled copy. probe/build-profile-gate.sh is its caller.
//
//   java -cp <the classpath EmitBuildProfile prints> \
//     agentsandbox.launcher.RunOnHost <sbt|mill> <project> [authority-file] -- <args...>
//
// Plain java, never `sbt Test/runMain`: runMain would host this in the build's own JVM, whose
// server holds the target project's portfile — the one-server-per-project refusal — and whose exit is sys.exit's.
// Exits with the build's code; a refusal is 2, on stderr.

package agentsandbox.launcher

import java.nio.file.Paths

import RunOnHostPolicy.Tool

object RunOnHost:

  def main(args: Array[String]): Unit =
    val (front, buildArgs) = args.toList.span(_ != "--") match
      case (before, "--" :: rest) => (before, rest)
      case (before, _)            => (before, Nil)

    val usage = "usage: RunOnHost <sbt|mill> <project> [authority-file] -- <args...>"
    front match
      case toolName :: projectName :: rest if rest.sizeIs <= 1 =>
        val tool = toolName.toLowerCase match
          case "sbt"  => Tool.Sbt
          case "mill" => Tool.Mill
          case other  => Console.err.println(s"unknown tool $other\n$usage"); sys.exit(2)
        val runtime = RunOnHostSandbox.readRuntimeAuthority(rest.headOption.map(Paths.get(_)))
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        sys.exit(
          RunOnHostSandbox.run(Paths.get(projectName), tool, buildArgs, runtime, uid, Console.err.println),
        )
      case _ =>
        Console.err.println(usage)
        sys.exit(2)
