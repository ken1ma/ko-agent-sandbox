package agentsandbox.launcher

import java.io.IOException
import java.lang.foreign.{Arena, FunctionDescriptor, Linker, MemoryLayout, MemorySegment, StructLayout, ValueLayout}
import scala.util.Using

/** Foreign Function and Memory API */
object FFMHelper:

  object libc:

    /** `execvp` replaces this process: same pid, terminal, signals and exit
      * status. A restricted method — the build bakes
      * `--enable-native-access=ALL-UNNAMED` into the manifest and run task.
      * The caller treats any throwable as "no exec on this platform" and
      * falls back to spawning and waiting.
      */
    def execvp(command: Vector[String]): Unit =
      val linker = Linker.nativeLinker()
      val captureLayout: StructLayout = Linker.Option.captureStateLayout()
      val errnoHandle = captureLayout.varHandle(MemoryLayout.PathElement.groupElement("errno"))
      val handle = linker.downcallHandle(
        linker.defaultLookup().find("execvp").orElseThrow(),
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
        Linker.Option.captureCallState("errno"),
      )
      Using.resource(Arena.ofConfined()): arena =>
        val file = arena.allocateFrom(command.head)
        val argv = arena.allocate(ValueLayout.ADDRESS, command.length + 1)
        command.zipWithIndex.foreach: (arg, i) =>
          argv.setAtIndex(ValueLayout.ADDRESS, i, arena.allocateFrom(arg))
        argv.setAtIndex(ValueLayout.ADDRESS, command.length, MemorySegment.NULL)
        val state = arena.allocate(captureLayout)
        // The `: Int` ascription is load-bearing: invokeExact is signature-polymorphic, so the expected type at the
        // call site selects the compiled method descriptor, and a mismatch with the handle's
        // (MemorySegment,MemorySegment,MemorySegment)int is a runtime WrongMethodTypeException. In bare statement
        // position the descriptor would be (...)void. The value itself is discarded: execvp only returns on failure,
        // and the captured errno below is the detail.
        val _: Int = handle.invokeExact(state, file, argv)
        val errno: Int = errnoHandle.get(state, 0L)
        throw IOException(s"execvp failed with errno $errno")
