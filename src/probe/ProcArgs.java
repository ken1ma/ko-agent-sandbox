// What a confined host command learns of another process of the same user through
// sysctl(KERN_PROCARGS2), the call behind `ps -E`: run-on-host-profile-iterate.sh's `procargs` mode
// runs this under the command profile, with and without a deny of that name. `ps` is no granted
// binary, and a build can make the kernel call itself, so the measurement does too. Counts and
// variable names only, never a value: the targets are the user's own processes.
//
//   java ProcArgs.java --hold               sleep until killed, as a target that is not Apple's binary
//   java ProcArgs.java <label>=<pid>...     read each target and report what came back
//   java ProcArgs.java --child=<this file>  start a held child, read it as a target, and end it
//
// Each target's line ends with whether `ProcessHandle.of` finds it, which the JDK answers through
// sysctl(KERN_PROC_PID), and whether `info()` reads its start time.
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ProcArgs {
    private static final int CTL_KERN = 1;
    private static final int KERN_PROCARGS2 = 49;
    private static final long BUFFER_BYTES = 1L << 20;
    /** Variables printed by name when present: proof that an environment came back, nothing more. */
    private static final List<String> NAMED = List.of("HOME", "PATH", "USER", "SHELL", "HTTPS_PROXY");

    public static void main(String[] args) throws Throwable {
        if (args.length == 1 && args[0].equals("--hold")) {
            Thread.sleep(Long.MAX_VALUE);
        }
        if (args.length == 0) {
            System.err.println("usage: java ProcArgs.java --hold | <label>=<pid>...");
            System.exit(2);
        }
        Linker linker = Linker.nativeLinker();
        StructLayout state = Linker.Option.captureStateLayout();
        long errnoOffset = state.byteOffset(MemoryLayout.PathElement.groupElement("errno"));
        MethodHandle sysctl = linker.downcallHandle(
            linker.defaultLookup().find("sysctl").orElseThrow(),
            FunctionDescriptor.of(
                ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS,
                ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
            Linker.Option.captureCallState("errno"));
        for (String arg : args) {
            int separator = arg.lastIndexOf('=');
            String label = arg.substring(0, separator);
            if (label.equals("--child")) {
                Process child = holdChild(arg.substring(separator + 1));
                try {
                    report("a child of the reader", child.pid(), sysctl, state, errnoOffset);
                } finally {
                    child.destroyForcibly();
                }
            } else {
                report(label, Long.parseLong(arg.substring(separator + 1)), sysctl, state, errnoOffset);
            }
        }
        // What a rule costs a build that inspects processes: the JDK lists them through
        // sysctl(kern.proc.all), which throws when the profile denies it.
        String listed;
        try {
            listed = Long.toString(ProcessHandle.allProcesses().count());
        } catch (RuntimeException ex) {
            listed = "DENIED (" + ex.getMessage() + ")";
        }
        System.out.println("processes ProcessHandle lists: " + listed);
    }

    private static void report(String label, long pid, MethodHandle sysctl, StructLayout state, long errnoOffset)
        throws Throwable {
        String found = ProcessHandle.of(pid).isPresent() ? "present" : "absent";
        // What Mill's client asks of its daemon (PidLock.isLockValid): on macOS the JDK reads the
        // target's arguments for info(), and throws when that read is refused.
        String info;
        try {
            info = ProcessHandle.of(pid).flatMap(handle -> handle.info().startInstant()).isPresent()
                ? "read" : "empty";
        } catch (RuntimeException ex) {
            info = "throws " + ex.getMessage();
        }
        System.out.println(label + " (pid " + pid + "): " + read(sysctl, state, errnoOffset, pid)
            + "; ProcessHandle.of " + found + "; info " + info);
    }

    /** A held JDK this process starts, so it inherits this process's sandbox, with the marker variable. */
    private static Process holdChild(String source) throws Exception {
        ProcessBuilder builder = new ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=" + System.getProperty("java.io.tmpdir"), source, "--hold");
        builder.environment().put("KO_AGENT_PROCARGS_PROBE", "child");
        builder.redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
        Process child = builder.start();
        Thread.sleep(500);
        return child;
    }

    private static String read(MethodHandle sysctl, StructLayout state, long errnoOffset, long pid) throws Throwable {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = arena.allocate(ValueLayout.JAVA_INT, 3);
            name.setAtIndex(ValueLayout.JAVA_INT, 0, CTL_KERN);
            name.setAtIndex(ValueLayout.JAVA_INT, 1, KERN_PROCARGS2);
            name.setAtIndex(ValueLayout.JAVA_INT, 2, (int) pid);
            MemorySegment buffer = arena.allocate(BUFFER_BYTES);
            MemorySegment length = arena.allocate(ValueLayout.JAVA_LONG);
            length.set(ValueLayout.JAVA_LONG, 0, BUFFER_BYTES);
            MemorySegment captured = arena.allocate(state);
            int rc = (int) sysctl.invokeExact(captured, name, 3, buffer, length, MemorySegment.NULL, 0L);
            if (rc != 0) {
                int errno = captured.get(ValueLayout.JAVA_INT, errnoOffset);
                return "DENIED errno=" + errno + " (" + errnoName(errno) + ")";
            }
            // The buffer is argc, the executable path, NUL padding, argc arguments, then the
            // environment, every string NUL-terminated. Counting by argc keeps an argument holding
            // '=' from reading as a variable.
            int argc = buffer.get(ValueLayout.JAVA_INT, 0);
            byte[] bytes = buffer.asSlice(4, length.get(ValueLayout.JAVA_LONG, 0) - 4).toArray(ValueLayout.JAVA_BYTE);
            int position = endOfString(bytes, 0);
            while (position < bytes.length && bytes[position] == 0) position++;
            int arguments = 0;
            while (arguments < argc && position < bytes.length) {
                position = endOfString(bytes, position) + 1;
                arguments++;
            }
            int variables = 0;
            List<String> names = new ArrayList<>();
            while (position < bytes.length) {
                int end = endOfString(bytes, position);
                String entry = new String(bytes, position, end - position, StandardCharsets.ISO_8859_1);
                int equals = entry.indexOf('=');
                if (equals > 0) {
                    variables++;
                    String variable = entry.substring(0, equals);
                    if (variable.startsWith("KO_AGENT") || NAMED.contains(variable)) names.add(variable);
                }
                position = end + 1;
            }
            if (variables == 0) return "ARGUMENTS ONLY arguments=" + arguments;
            return "ENVIRONMENT READ arguments=" + arguments + " variables=" + variables
                + " names=" + String.join(",", names);
        }
    }

    private static int endOfString(byte[] bytes, int from) {
        int position = from;
        while (position < bytes.length && bytes[position] != 0) position++;
        return position;
    }

    private static String errnoName(int errno) {
        return switch (errno) {
            case 1 -> "EPERM: the profile denied it";
            case 3 -> "ESRCH: no such process";
            case 22 -> "EINVAL: the kernel refused it";
            default -> "errno " + errno;
        };
    }
}
