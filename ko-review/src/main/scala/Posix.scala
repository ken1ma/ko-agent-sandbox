package koreview

import java.io.IOException
import java.nio.charset.StandardCharsets.ISO_8859_1
import java.lang.foreign.{Arena, FunctionDescriptor, Linker, MemoryLayout, MemorySegment, StructLayout, ValueLayout}
import java.nio.file.{Files, LinkOption, Path}
import java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE
import scala.jdk.CollectionConverters.*
import scala.util.Using

/** The process control that the JVM's Process API lacks: process groups, a signal to a group, Linux's child
  * subreaper, and the reaping of processes that the JVM did not start. The object uses no ko-review type, so that it
  * can move into a library of its own.
  *
  * The calls are restricted FFM methods: without `--enable-native-access=ALL-UNNAMED` every call prints a warning,
  * and a later JDK refuses it.
  */
object Posix:

  val SIGKILL = 9
  private val ESRCH = 3
  private val EINTR = 4
  private val ECHILD = 10
  private val PR_SET_CHILD_SUBREAPER = 36 // prctl(2)

  val isLinux: Boolean = System.getProperty("os.name") == "Linux"

  /** Git records the owner's execute bit; an access check also depends on the user and the mount's noexec flag. */
  def ownerExecutable(path: Path): Boolean =
    Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).contains(OWNER_EXECUTE)

  private lazy val linker = Linker.nativeLinker()
  private lazy val captureLayout: StructLayout = Linker.Option.captureStateLayout()
  private lazy val errnoHandle = captureLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"))

  private val int = ValueLayout.JAVA_INT

  /** Calls the C library's function `name` and returns its int result with the errno it left. */
  private def call(name: String, descriptor: FunctionDescriptor, arguments: AnyRef*)(using arena: Arena): (Int, Int) =
    val handle = linker.downcallHandle(
      linker.defaultLookup().find(name).orElseThrow(),
      descriptor,
      Linker.Option.captureCallState("errno"),
    )
    val state = arena.allocate(captureLayout)
    val result = handle.invokeWithArguments((state +: arguments)*).asInstanceOf[Int]
    val errno: Int = errnoHandle.get(state, 0L)
    (result, errno)

  private def withArena[T](body: Arena ?=> T): T = Using.resource(Arena.ofConfined())(arena => body(using arena))

  /** `setpgid(pid, pgid)`; `pid` 0 is this process, and `pgid` 0 makes a group that `pid` leads. */
  def setpgid(pid: Long, pgid: Long): Unit = withArena:
    val (result, errno) = call("setpgid", FunctionDescriptor.of(int, int, int), Int.box(pid.toInt), Int.box(pgid.toInt))
    if result != 0 then throw IOException(s"setpgid($pid, $pgid) failed with errno $errno")

  /** The process group of `pid`, or None once the process is gone. */
  def getpgid(pid: Long): Option[Long] = withArena:
    val (result, _) = call("getpgid", FunctionDescriptor.of(int, int), Int.box(pid.toInt))
    Option.when(result >= 0)(result.toLong)

  /** Sends `signal` to every process of the group, and answers false when the group is gone. */
  def killGroup(pgid: Long, signal: Int): Boolean = withArena:
    val (result, errno) = call("killpg", FunctionDescriptor.of(int, int, int), Int.box(pgid.toInt), Int.box(signal))
    if result == 0 then true
    else if errno == ESRCH then false
    else throw IOException(s"killpg($pgid, $signal) failed with errno $errno")

  /** Sends `signal` to `pid`, and answers false when the process is gone. */
  def kill(pid: Long, signal: Int): Boolean = withArena:
    val (result, errno) = call("kill", FunctionDescriptor.of(int, int, int), Int.box(pid.toInt), Int.box(signal))
    if result == 0 then true
    else if errno == ESRCH then false
    else throw IOException(s"kill($pid, $signal) failed with errno $errno")

  /** Waits for the child `pid` to end and reaps it. A child that is already reaped returns at once. Use it only for a
    * child that the JVM did not start: the JVM reaps its own children. */
  def reap(pid: Long): Unit = withArena:
    val status = summon[Arena].allocate(int)
    var done = false
    while !done do
      val (result, errno) = call(
        "waitpid",
        FunctionDescriptor.of(int, int, ValueLayout.ADDRESS, int),
        Int.box(pid.toInt),
        status,
        Int.box(0),
      )
      if result >= 0 || errno == ECHILD then done = true
      else if errno != EINTR then throw IOException(s"waitpid($pid) failed with errno $errno")

  /** On Linux, while enabled, a descendant whose parent exits becomes this process's child instead of init's,
    * whatever session or group the descendant moved to. Elsewhere this does nothing. */
  def setChildSubreaper(enabled: Boolean): Unit =
    if isLinux then
      withArena:
        val (result, errno) = call(
          "prctl",
          FunctionDescriptor.of(int, int, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG,
            ValueLayout.JAVA_LONG),
          Int.box(PR_SET_CHILD_SUBREAPER),
          Long.box(if enabled then 1L else 0L),
          Long.box(0L),
          Long.box(0L),
          Long.box(0L),
        )
        if result != 0 then throw IOException(s"prctl(PR_SET_CHILD_SUBREAPER) failed with errno $errno")

  /** The target of the symlink at `link`, byte for byte: a JVM Path decodes it, and loses bytes that are not UTF-8
    * and repeated or trailing slashes. */
  def readlink(link: Path): Array[Byte] = withArena:
    val arena = summon[Arena]
    val handle = linker.downcallHandle(
      linker.defaultLookup().find("readlink").orElseThrow(),
      FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
      Linker.Option.captureCallState("errno"),
    )
    var size = 4096L
    var target: Option[Array[Byte]] = None
    while target.isEmpty do
      val state = arena.allocate(captureLayout)
      val buffer = arena.allocate(size)
      val length = handle.invokeWithArguments(state, arena.allocateFrom(link.toString), buffer, Long.box(size))
        .asInstanceOf[Long]
      if length < 0 then
        val errno: Int = errnoHandle.get(state, 0L)
        throw IOException(s"readlink $link failed with errno $errno")
      if length < size then target = Some(buffer.asSlice(0, length).toArray(ValueLayout.JAVA_BYTE))
      else size *= 2
    target.get

  /** Creates a symlink at `link` whose target is `target`, byte for byte. */
  def symlink(target: Array[Byte], link: Path): Unit = withArena:
    val arena = summon[Arena]
    val bytes = arena.allocate(target.length + 1L)
    bytes.copyFrom(MemorySegment.ofArray(target))
    bytes.set(ValueLayout.JAVA_BYTE, target.length.toLong, 0.toByte)
    val (result, errno) = call("symlink", FunctionDescriptor.of(int, ValueLayout.ADDRESS, ValueLayout.ADDRESS), bytes,
      arena.allocateFrom(link.toString))
    if result != 0 then throw IOException(s"symlink $link failed with errno $errno")

  /** Replaces this process with `command`, found on the PATH as a shell would. Returns only by throwing. */
  def execvp(command: Seq[String]): Nothing = withArena:
    val arena = summon[Arena]
    val argv = arena.allocate(ValueLayout.ADDRESS, command.length + 1L)
    for (argument, i) <- command.zipWithIndex do
      argv.setAtIndex(ValueLayout.ADDRESS, i.toLong, arena.allocateFrom(argument))
    argv.setAtIndex(ValueLayout.ADDRESS, command.length.toLong, MemorySegment.NULL)
    val (_, errno) = call(
      "execvp",
      FunctionDescriptor.of(int, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
      arena.allocateFrom(command.head),
      argv,
    )
    throw IOException(s"execvp ${command.head} failed with errno $errno")

  /** The children of `pid`, read from /proc on Linux, and none elsewhere. */
  def childrenOf(pid: Long): Seq[Long] =
    if !isLinux then Nil
    else
      Using.resource(Files.list(Path.of("/proc"))): entries =>
        entries.iterator().asScala.toVector.flatMap: entry =>
          val name = entry.getFileName.toString
          if !name.forall(_.isDigit) then None
          else
            try
              val stat = Files.readAllBytes(entry.resolve("stat"))
              // The parent is the second field after the parenthesized command, which holds any bytes, ")" included.
              val end = stat.lastIndexOf(')'.toByte)
              val afterCommand = String(stat, end + 1, stat.length - end - 1, ISO_8859_1)
              val fields = afterCommand.trim.split("\\s+")
              Option.when(fields(1).toLong == pid)(name.toLong)
            catch case _: IOException => None // gone meanwhile

  /** On Linux, kills and reaps every child of this process, in passes until none is left. A killed child's children
    * are adopted while the subreaper is set, and the next pass finds them. Elsewhere this does nothing. */
  def killAndReapChildren(): Unit =
    var children = childrenOf(ProcessHandle.current().pid())
    while children.nonEmpty do
      children.foreach(kill(_, SIGKILL))
      children.foreach(reap)
      children = childrenOf(ProcessHandle.current().pid())

/** Joins a process group, then becomes the given command: `JoinGroup <pgid> <program> <arguments>…`, where pgid 0
  * makes a group that the process leads. The JVM cannot set a child's group between fork and exec, so a process
  * that must start in a group starts as this program. */
object JoinGroup:
  def main(arguments: Array[String]): Unit =
    try
      Posix.setpgid(0, arguments(0).toLong)
      Posix.execvp(arguments.toSeq.drop(1))
    catch
      case ex: Exception =>
        System.err.println(s"ko-review: ${ex.getMessage}")
        System.exit(127)
