package agentsandbox.launcher

/** The suites that run the reaper's shell for real need the `ps` its tree functions walk with. */
object HostPs:

  /** This host's `ps`, probed for the exact arguments the harnesses parse — `-A -o pid=,ppid=,stat=`,
    * the launcher's own plus `stat=` — so an incompatible one (BusyBox), or one a sandbox keeps from
    * listing processes (the run-on-host Seatbelt profile), skips the suite rather than failing it. */
  def answering(): String =
    val found = HostCommands.findOnPath("ps", sys.env.getOrElse("PATH", ""), HostCommands.currentOs)
    munit.Assertions.assume(found.isDefined, "needs ps on PATH")
    val ps = found.get.toString
    val me = ProcessHandle.current.pid.toString
    val answers =
      try HostCommands.run(ps, "-A", "-o", "pid=,ppid=,stat=").text.linesIterator
          .exists(line => line.trim.split("\\s+").toList match
            case pid :: _ :: stat :: Nil => pid == me && stat.nonEmpty
            case _ => false)
      catch case _: java.io.IOException => false
    munit.Assertions.assume(answers, s"needs a ps answering `ps -A -o pid=,ppid=,stat=`; $ps did not")
    ps
