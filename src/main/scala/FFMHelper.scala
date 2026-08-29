package agentsandbox.launcher

import java.io.IOException
import java.lang.foreign.{Arena, FunctionDescriptor, Linker, MemoryLayout, MemorySegment, StructLayout, ValueLayout}
import scala.util.Using

object FFMHelper:

  object libc:

    /** `isatty`. The launcher asks it about stderr, where its own lines go and which a reader
      * redirects to keep them, so `System.console()` — which answers for stdin — is a different
      * question. Restricted, as execvp below.
      *
      * Every failure answers "not a terminal": the first caller is `fail`, and a platform without
      * the symbol, or one that denies the call, must lose the colour rather than the refusal text.
      */
    def isatty(fd: Int): Boolean =
      try
        val linker = Linker.nativeLinker()
        val handle = linker.downcallHandle(
          linker.defaultLookup().find("isatty").orElseThrow(),
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT),
        )
        // The ascription is load-bearing for the same reason as in execvp below.
        val answer: Int = handle.invokeExact(fd)
        answer != 0
      catch case _: Throwable => false

    /** A restricted method — the build bakes `--enable-native-access=ALL-UNNAMED` into the
      * manifest and run task. Returns only by throwing (SandboxLifecycle.handOver has the fallback).
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
