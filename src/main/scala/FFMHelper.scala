package agentsandbox.launcher

import java.io.IOException
import java.lang.foreign.{
  Arena, FunctionDescriptor, Linker, MemoryLayout, MemorySegment, StructLayout, SymbolLookup, ValueLayout,
}
import scala.util.Using

object FFMHelper:

  object kernel32:

    // ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING: SetConsoleMode's documentation
    // asks for the first wherever the second is used, and an inherited mode can lack it.
    private val EscapeProcessing = 0x0001 | 0x0004

    /** Whether the console behind `fd` (1 or 2) renders escape sequences, asking it to if it does
      * not yet: a console only interprets them under ENABLE_VIRTUAL_TERMINAL_PROCESSING, and
      * prints them as text otherwise. GetConsoleMode fails on a redirected stream, so this is
      * also Windows' `isatty`. The mode is left set at exit, as the shells and Windows Terminal
      * set it themselves.
      *
      * Every failure answers false, as `libc.isatty` below. kernel32 is one of the KnownDLLs, which
      * Windows loads from System32 whatever the search path holds.
      */
    def enableVirtualTerminalProcessing(fd: Int): Boolean =
      try
        val linker = Linker.nativeLinker()
        val lookup = SymbolLookup.libraryLookup("kernel32", Arena.global())
        def function(name: String, descriptor: FunctionDescriptor) =
          linker.downcallHandle(lookup.find(name).orElseThrow(), descriptor)
        val getStdHandle =
          function("GetStdHandle", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT))
        val getConsoleMode = function(
          "GetConsoleMode",
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
        )
        val setConsoleMode = function(
          "SetConsoleMode",
          FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
        )
        Using.resource(Arena.ofConfined()): arena =>
          // STD_OUTPUT_HANDLE is -11 and STD_ERROR_HANDLE -12.
          val console: MemorySegment = getStdHandle.invokeExact(-10 - fd)
          val mode = arena.allocate(ValueLayout.JAVA_INT)
          val isConsole: Int = getConsoleMode.invokeExact(console, mode)
          val current = mode.get(ValueLayout.JAVA_INT, 0L)
          if isConsole == 0 then false
          else if (current & EscapeProcessing) == EscapeProcessing then true
          else
            val accepted: Int = setConsoleMode.invokeExact(console, current | EscapeProcessing)
            accepted != 0
      catch case _: Throwable => false

    /** `SetEnvironmentVariableW(name, NULL)`: the variable gone from what a process this one creates
      * inherits. Throws on failure: a value a child should not inherit must not be left there quietly. */
    def clearEnvironmentVariable(name: String): Unit =
      val linker = Linker.nativeLinker()
      val lookup = SymbolLookup.libraryLookup("kernel32", Arena.global())
      val handle = linker.downcallHandle(
        lookup.find("SetEnvironmentVariableW").orElseThrow(),
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
      )
      Using.resource(Arena.ofConfined()): arena =>
        val terminated = (name + "\u0000").getBytes(java.nio.charset.StandardCharsets.UTF_16LE)
        val wide = arena.allocateFrom(ValueLayout.JAVA_BYTE, terminated*)
        val cleared: Int = handle.invokeExact(wide, MemorySegment.NULL)
        if cleared == 0 then throw IOException(s"SetEnvironmentVariableW could not remove $name")

  object libc:

    /** `isatty`. The launcher asks it about the stream a line goes to — stderr for its own lines,
      * stdout for the `--stats` report — which a reader redirects to keep them, so
      * `System.console()` — which answers for stdin — is a different question. Restricted, as
      * execvp below.
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
        // The ascription is necessary for the same reason as in execvp below.
        val answer: Int = handle.invokeExact(fd)
        answer != 0
      catch case _: Throwable => false

    /** `unsetenv`: the variable gone from what a process this one starts inherits. Throws on failure,
      * as kernel32.clearEnvironmentVariable does. */
    def unsetenv(name: String): Unit =
      val linker = Linker.nativeLinker()
      val handle = linker.downcallHandle(
        linker.defaultLookup().find("unsetenv").orElseThrow(),
        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
      )
      Using.resource(Arena.ofConfined()): arena =>
        val removed: Int = handle.invokeExact(arena.allocateFrom(name))
        if removed != 0 then throw IOException(s"unsetenv could not remove $name")

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
        // The `: Int` ascription is necessary: invokeExact is signature-polymorphic, so the expected type at the
        // call site selects the compiled method descriptor, and a mismatch with the handle's
        // (MemorySegment,MemorySegment,MemorySegment)int is a runtime WrongMethodTypeException. In bare statement
        // position the descriptor would be (...)void. The value itself is discarded: execvp only returns on failure,
        // and the captured errno below is the detail.
        val _: Int = handle.invokeExact(state, file, argv)
        val errno: Int = errnoHandle.get(state, 0L)
        throw IOException(s"execvp failed with errno $errno")
