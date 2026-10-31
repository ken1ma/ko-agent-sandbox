package agentsandbox.launcher

/** The `ps` that the reaper's tree functions walk the process tree with. The suites that run the reaper's shell for
  * real need it. */
object HostPs:

  /** This host's `ps`, probed with the exact arguments that the harnesses parse: `-A -o pid=,ppid=,stat=`, which are
    * the launcher's own arguments plus `stat=`. The suite skips rather than fails in two cases:
    * - the `ps` is incompatible, such as BusyBox's;
    * - a sandbox keeps the `ps` from listing processes, such as the run-on-host Seatbelt profile. */
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
