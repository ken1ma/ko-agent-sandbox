package agentsandbox.launcher

import java.nio.channels.FileChannel
import java.nio.file.{Path, StandardOpenOption}

/** A second process that tries to lock a file. Only another process can observe an fcntl lock that this JVM holds.
  *
  * `java -cp <test classpath> agentsandbox.launcher.RunOnHostLockProbe <file>` prints `taken` when it could lock the
  * file and `held` when another process holds the lock. The probe then exits and releases any lock it took. */
object RunOnHostLockProbe:
  def main(args: Array[String]): Unit =
    val channel = FileChannel.open(Path.of(args(0)), StandardOpenOption.WRITE)
    val lock = channel.tryLock()
    println(if lock == null then "held" else "taken")
    channel.close()
