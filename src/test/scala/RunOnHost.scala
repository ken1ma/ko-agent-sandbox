// The acceptance test's supervisor driver, a sibling of EmitRunOnHostProfile. The driver runs the RunOnHostSandbox
// supervisor and takes the system-paths file as an argument. The durable front end, the launcher's
// --run-command-on-host action behind the channel, reads the bundled copy of that file instead.
// src/probe/run-on-host-acceptance-test.sh calls this driver.
//
//   java -cp <the classpath EmitRunOnHostProfile prints> \
//     agentsandbox.launcher.RunOnHost <program> <workspace> [system-paths-file] -- <args...>
//
// The acceptance test runs that command through perl's exec, under the build lock that the runner's lock holder takes
// (RunOnHostSession.lockedSpawn). The pid that the kill rows signal is therefore the supervisor's.
// The acceptance test composes that command from two outputs of this driver:
// - `--lock-script` prints the perl script.
// - `--build-lock <program> <workspace>` prints the lock file.
//
// The acceptance test runs plain java, never `sbt Test/runMain`, for two reasons:
// - runMain would host the supervisor in the build's own JVM. That JVM's server holds the target workspace's portfile,
//   and the supervisor would end that server, since a build directory has one server.
// - The driver's sys.exit would exit the build's JVM.
// The driver exits with the command's exit code. A refusal exits with 2 and prints its reason on stderr.

package agentsandbox.launcher

import java.nio.file.Paths

import RunOnHostPrereqs.Program

object RunOnHost:

  def main(args: Array[String]): Unit =
    val (front, commandArgs) = args.toList.span(_ != "--") match
      case (before, "--" :: rest) => (before, rest)
      case (before, _)            => (before, Nil)

    val usage =
      s"usage: RunOnHost <${Program.values.map(_.name).mkString("|")}> <workspace> [system-paths-file] -- <args...>"
    front match
      case "--lock-script" :: Nil => print(RunOnHostSession.LockScript)
      case "--build-lock" :: programName :: workspacePath :: Nil =>
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        val root = RunOnHostSession.root(uid)
        RunOnHostSession.ensureRoot(root, uid)
          .flatMap(_ => RunOnHostSession.buildLockFile(root, programName.toLowerCase, Paths.get(workspacePath)))
          .fold(reason => { Console.err.println(s"refused: $reason"); sys.exit(2) }, println)
      case programName :: workspacePath :: rest if rest.sizeIs <= 1 =>
        val program = Program.named(programName.toLowerCase).getOrElse:
          Console.err.println(s"unknown program $programName\n$usage")
          sys.exit(2)
        val systemPaths = RunOnHostSandbox.readSystemPaths(rest.headOption.map(Paths.get(_)))
        val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
        sys.exit(
          RunOnHostSandbox.run(Paths.get(workspacePath), program, commandArgs, systemPaths, uid, Console.err.println),
        )
      case _ =>
        Console.err.println(usage)
        sys.exit(2)
