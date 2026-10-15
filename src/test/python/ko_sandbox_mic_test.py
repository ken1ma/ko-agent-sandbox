"""ko-sandbox-mic's controller and writer against a pactl stand-in: the demand they read from the
daemon's listings, the `start` the controller writes to the relay's FIFO, the writer it signals,
and the writer's contract with the relay (`ready` only once the FIFO is open, unbuffered). Then
the image's daemon, where it is installed: what it touches, the boundary between recordings, and
audio through the writer sample for sample."""

import fcntl
import importlib.machinery
import importlib.util
import itertools
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PROJECT = Path(__file__).resolve().parents[3]
PROGRAM = PROJECT / "container/ko-agent-sandbox/microphone/ko-sandbox-mic"
# Loaded as a module without its bytecode cache, which would land in the image's build context.
sys.dont_write_bytecode = True
_loader = importlib.machinery.SourceFileLoader("ko_sandbox_mic", str(PROGRAM))
_spec = importlib.util.spec_from_loader("ko_sandbox_mic", _loader)
mic = importlib.util.module_from_spec(_spec)
_loader.exec_module(mic)

SOURCES = "0\tfifo_input\tmodule-pipe-source.c\ts16le 1ch 16000Hz\tRUNNING\n" \
    "1\tspeaker.monitor\tmodule-null-sink.c\ts16le 1ch 16000Hz\tIDLE\n"
LOOPBACK = "0\t0\t-\tmodule-loopback.c\ts16le 1ch 16000Hz\n"
CLIENT = "7\t0\t12\tprotocol-native.c\ts16le 1ch 16000Hz\n"
MONITOR_CLIENT = "8\t1\t13\tprotocol-native.c\ts16le 1ch 16000Hz\n"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class ReapingTest(unittest.TestCase):
    def reaped(self, process):
        def end():
            process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream:
                    stream.close()
        self.addCleanup(end)
        return process


class MicTest(ReapingTest):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ko-sandbox-mic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.directory = self.root / "microphone"
        self.directory.mkdir()
        # The stand-in answers each listing from the file `sources` or `outputs`, and appends a
        # client event to `clients`, as the daemon reports a listing's client. `subscribe` waits
        # `subscribe-delay` seconds to register, then prints the new lines of `clients` and the lines
        # of the FIFO `events`, until the FIFO's writer closes it.
        (self.root / "sources").write_text(SOURCES)
        (self.root / "clients").write_text("")
        self.outputs(LOOPBACK)
        os.mkfifo(self.root / "events")
        pactl = self.bin / "pactl"
        pactl.write_text(
            "#!/bin/sh\n"
            f'case "$*" in\n'
            f'  "list short sources") cat "{self.root}/sources" ;;\n'
            f'  "list short source-outputs") cat "{self.root}/outputs" ;;\n'
            "  subscribe)\n"
            f'    sleep "$(cat "{self.root}/subscribe-delay" 2>/dev/null || echo 0)"\n'
            f'    tail -n 0 -f "{self.root}/clients" & clients=$!\n'
            f'    cat "{self.root}/events"; kill "$clients"; exit 0 ;;\n'
            "  *) exit 1 ;;\n"
            "esac\n"
            f'echo "Event \'new\' on client #$$" >> "{self.root}/clients"\n',
        )
        pactl.chmod(0o755)
        self.saved_path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bin}:{self.saved_path}"
        self.addCleanup(os.environ.__setitem__, "PATH", self.saved_path)

    def outputs(self, text):
        (self.root / "outputs").write_text(text)

    def request_reader(self):
        """The relay's side of `req`: a FIFO held open for reading, as its exec holds it."""
        os.mkfifo(self.directory / "req")
        fd = os.open(self.directory / "req", os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, fd)
        return fd

    def requests(self, fd):
        try:
            return os.read(fd, 4096).decode()
        except BlockingIOError:
            return ""

    def controller_process(self):
        """A process standing in for the controller, with its pid file as the controller writes it."""
        process = self.reaped(subprocess.Popen(["sleep", "60"]))
        (self.directory / mic.CONTROLLER_PID_FILE).write_text(f"{process.pid} {mic.start_time(process.pid)}\n")
        return process

    def daemon_fifo(self):
        """The daemon's FIFO, held open read-write as the daemon holds it, by a reader that never blocks."""
        fifo = self.directory / "mic"
        os.mkfifo(fifo)
        reader = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        self.addCleanup(os.close, reader)
        return fifo, reader

    def drain(self, reader):
        try:
            return os.read(reader, 1 << 20)
        except BlockingIOError:
            return b""

    def writer_process(self):
        """A process standing in for a live writer, with its pid file as the writer writes it."""
        process = self.reaped(subprocess.Popen(["sleep", "60"]))
        (self.directory / mic.WRITER_PID_FILE).write_text(f"{process.pid} {mic.start_time(process.pid)}\n")
        return process

    def test_demand_counts_client_streams_on_the_microphone_only(self):
        self.assertEqual(mic.source_index(), "0")
        self.assertEqual(mic.recording_streams("0"), 0)
        self.outputs(LOOPBACK + MONITOR_CLIENT)
        self.assertEqual(mic.recording_streams("0"), 0)
        self.outputs(LOOPBACK + CLIENT + MONITOR_CLIENT)
        self.assertEqual(mic.recording_streams("0"), 1)

    def test_start_on_demand_without_supply_and_not_again_within_the_wait(self):
        fd = self.request_reader()
        clock = Clock()
        controller = mic.Controller(str(self.directory), "0", clock)
        controller.reconcile()
        self.assertEqual(self.requests(fd), "")
        self.outputs(LOOPBACK + CLIENT)
        controller.reconcile()
        self.assertEqual(self.requests(fd), "start\n")
        clock.now += mic.START_WAIT_SECONDS - 0.1
        controller.reconcile()
        self.assertEqual(self.requests(fd), "")
        self.assertAlmostEqual(controller.deadline(), 0.1, places=5)
        # The wait passed with no writer: the exec was slow or failed, so another start.
        clock.now += 0.1
        controller.reconcile()
        self.assertEqual(self.requests(fd), "start\n")

    def test_a_writer_that_dies_under_demand_gets_a_new_start(self):
        fd = self.request_reader()
        clock = Clock()
        self.outputs(LOOPBACK + CLIENT)
        writer = self.writer_process()
        controller = mic.Controller(str(self.directory), "0", clock)
        controller.reconcile()
        self.assertEqual(self.requests(fd), "", "a start beside a live writer")
        writer.kill()
        writer.wait()
        controller.reconcile()
        self.assertEqual(self.requests(fd), "start\n")

    def test_events_that_reconcile_nothing_never_postpone_the_timer(self):
        fd = self.request_reader()
        clock = Clock()
        self.outputs(LOOPBACK + CLIENT)
        writer = self.writer_process()
        controller = mic.Controller(str(self.directory), "0", clock)
        controller.reconcile()
        writer.kill()
        writer.wait()
        # A client event every second, as another program's listings make them.
        sent = ""
        for _ in range(int(mic.TICK_SECONDS) + 1):
            clock.now += 1
            controller.woken([b"Event 'new' on client #14"])
            sent += self.requests(fd)
        self.assertEqual(sent, "start\n")

    def test_a_writer_without_demand_is_terminated(self):
        self.request_reader()
        writer = self.writer_process()
        controller = mic.Controller(str(self.directory), "0", Clock())
        controller.reconcile()
        self.assertEqual(writer.wait(timeout=5), -signal.SIGTERM)

    def test_a_pid_file_naming_another_process_is_no_supply(self):
        fd = self.request_reader()
        self.outputs(LOOPBACK + CLIENT)
        other = self.reaped(subprocess.Popen(["sleep", "60"]))
        # The pid is alive, but its start time is not the recorded one: a reused pid.
        (self.directory / mic.WRITER_PID_FILE).write_text(f"{other.pid} 1\n")
        controller = mic.Controller(str(self.directory), "0", Clock())
        controller.reconcile()
        self.assertEqual(self.requests(fd), "start\n")
        self.outputs(LOOPBACK)
        controller.reconcile()
        self.assertIsNone(other.poll(), "a process the pid file does not name was signalled")

    def test_an_absent_or_unread_request_fifo_is_retried_soon_without_a_wait(self):
        clock = Clock()
        self.outputs(LOOPBACK + CLIENT)
        controller = mic.Controller(str(self.directory), "0", clock)
        controller.reconcile()
        self.assertTrue(controller.undelivered, "ENOENT")
        self.assertAlmostEqual(controller.deadline(), mic.UNDELIVERED_RETRY_SECONDS, places=5)
        os.mkfifo(self.directory / "req")
        controller.reconcile()
        self.assertTrue(controller.undelivered, "ENXIO")
        fd = os.open(self.directory / "req", os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, fd)
        controller.reconcile()
        self.assertFalse(controller.undelivered)
        self.assertEqual(self.requests(fd), "start\n")

    def test_the_controller_reacts_to_stream_events_and_exits_with_the_subscription(self):
        fd = self.request_reader()
        process = self.reaped(subprocess.Popen(
            [sys.executable, "-I", str(PROGRAM), "control", str(self.directory)], env=dict(os.environ),
        ))
        events = open(self.root / "events", "w")
        time.sleep(0.5)
        self.outputs(LOOPBACK + CLIENT)
        # A client event is not a stream event, and is no reason to list.
        events.write("Event 'new' on client #14\n")
        events.flush()
        time.sleep(0.5)
        self.assertEqual(self.requests(fd), "")
        events.write("Event 'new' on source-output #7\n")
        events.flush()
        deadline = time.monotonic() + 3
        received = ""
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
            received = self.requests(fd)
        self.assertEqual(received, "start\n")
        events.close()
        self.assertEqual(process.wait(timeout=5), 0)

    def test_a_stream_opened_before_the_subscription_registers_gets_a_start(self):
        fd = self.request_reader()
        (self.root / "subscribe-delay").write_text("1")
        # Read-write, so the open does not wait for the subscription's reader.
        events = os.open(self.root / "events", os.O_RDWR)
        self.addCleanup(os.close, events)
        # A controller, then the one the entrypoint starts again after it.
        for run in ("first", "restarted"):
            self.outputs(LOOPBACK)
            controller = self.reaped(subprocess.Popen(
                [sys.executable, "-I", str(PROGRAM), "control", str(self.directory)], env=dict(os.environ),
            ))
            # After a listing at the start would have run, before the subscription registers; the
            # stand-in reports no event for it, so only a listing finds it before the timer.
            time.sleep(0.5)
            self.outputs(LOOPBACK + CLIENT)
            deadline = time.monotonic() + 3
            received = ""
            while not received and time.monotonic() < deadline:
                time.sleep(0.05)
                received = self.requests(fd)
            self.assertEqual(received, "start\n", run)
            controller.kill()
            controller.wait()

    def test_a_stream_closing_while_the_writer_forwards_ends_the_writer_through_the_controller(self):
        self.request_reader()
        self.outputs(LOOPBACK + CLIENT)
        events = os.open(self.root / "events", os.O_RDWR)
        self.addCleanup(os.close, events)
        self.reaped(subprocess.Popen(
            [sys.executable, "-I", str(PROGRAM), "control", str(self.directory)], env=dict(os.environ),
        ))
        deadline = time.monotonic() + 3
        while not (self.directory / mic.CONTROLLER_PID_FILE).exists():
            self.assertLess(time.monotonic(), deadline, "the controller wrote no pid file")
            time.sleep(0.05)
        fifo, _ = self.daemon_fifo()
        writer = self.write(fifo)
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        # The writer's pid file came before its `ready`: from its demand check on, it is supply.
        self.outputs(LOOPBACK)
        os.write(events, b"Event 'remove' on source-output #7\n")
        self.assertEqual(writer.wait(timeout=2), 0, "the controller left the writer forwarding")
        self.assertFalse((self.directory / mic.WRITER_PID_FILE).exists())

    def write(self, fifo, stdin=subprocess.PIPE):
        return self.reaped(subprocess.Popen(
            [sys.executable, "-I", str(PROGRAM), "write", str(fifo)],
            stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ),
        ))

    def test_a_writer_without_demand_exits_without_a_word(self):
        fifo = self.directory / "mic"
        os.mkfifo(fifo)
        writer = self.write(fifo)
        out, _ = writer.communicate(timeout=5)
        self.assertEqual((writer.returncode, out), (0, b""))
        self.assertFalse((self.directory / mic.WRITER_PID_FILE).exists())

    def test_the_writer_says_ready_once_the_fifo_is_open_and_copies_until_terminated(self):
        self.outputs(LOOPBACK + CLIENT)
        self.controller_process()
        fifo, reader = self.daemon_fifo()
        writer = self.write(fifo)
        # `ready` arrives while the writer waits on stdin: written unbuffered.
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        pid, _ = (self.directory / mic.WRITER_PID_FILE).read_text().split()
        self.assertEqual(int(pid), writer.pid)
        writer.stdin.write(b"\x01\x02" * 320)
        writer.stdin.flush()
        deadline = time.monotonic() + 3
        received = b""
        while len(received) < 640 and time.monotonic() < deadline:
            time.sleep(0.05)
            try:
                received += os.read(reader, 4096)
            except BlockingIOError:
                pass
        self.assertEqual(received, b"\x01\x02" * 320, "the writer held audio")
        # SIGTERM interrupts the blocked read, and the writer removes its pid file.
        writer.send_signal(signal.SIGTERM)
        self.assertEqual(writer.wait(timeout=5), 0)
        self.assertFalse((self.directory / mic.WRITER_PID_FILE).exists())

    def test_the_writer_never_says_ready_without_a_fifo_it_can_open(self):
        self.outputs(LOOPBACK + CLIENT)
        self.controller_process()
        target = self.directory / "mic"
        target.write_text("")
        writer = self.write(target)
        out, _ = writer.communicate(timeout=5)
        self.assertEqual((writer.returncode, out), (1, b""))
        target.unlink()
        # A FIFO nobody reads: the daemon is gone.
        os.mkfifo(target)
        writer = self.write(target)
        out, _ = writer.communicate(timeout=5)
        self.assertNotEqual(writer.returncode, 0)
        self.assertEqual(out, b"")
        self.assertTrue(stat.S_ISFIFO(os.lstat(target).st_mode))
        self.assertFalse((self.directory / mic.WRITER_PID_FILE).exists())

    def test_the_writer_never_says_ready_without_its_controller(self):
        self.outputs(LOOPBACK + CLIENT)
        fifo, _ = self.daemon_fifo()
        writer = self.write(fifo)
        out, _ = writer.communicate(timeout=5)
        self.assertEqual((writer.returncode, out), (1, b""), "no controller pid file")
        # A live process whose start time is not the recorded one: the controller's pid, reused.
        other = self.reaped(subprocess.Popen(["sleep", "60"]))
        (self.directory / mic.CONTROLLER_PID_FILE).write_text(f"{other.pid} 1\n")
        writer = self.write(fifo)
        out, _ = writer.communicate(timeout=5)
        self.assertEqual((writer.returncode, out), (1, b""), "a reused controller pid")

    def test_frames_are_whole_and_atomic(self):
        self.assertEqual(mic.frame_prefix(b""), 0)
        self.assertEqual(mic.frame_prefix(b"a"), 0)
        self.assertEqual(mic.frame_prefix(b"abc"), 2)
        self.assertEqual(mic.frame_prefix(bytes(100001)), select.PIPE_BUF)
        self.assertEqual(select.PIPE_BUF % 2, 0)

    def test_fragments_of_odd_lengths_reach_the_fifo_as_whole_frames_in_order(self):
        self.outputs(LOOPBACK + CLIENT)
        self.controller_process()
        fifo, reader = self.daemon_fifo()
        writer = self.write(fifo)
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        sent = bytes(range(256)) * 64
        received = b""
        offset = 0
        for length in (1, 333, 7, 4097, 1, 9000, 65, 2880):
            writer.stdin.write(sent[offset:offset + length])
            writer.stdin.flush()
            offset += length
            time.sleep(0.1)
            got = self.drain(reader)
            # Everything the FIFO holds after a pause is whole frames: no write split one.
            self.assertEqual(len(got) % 2, 0, f"after {offset} bytes")
            received += got
        self.assertEqual(offset, len(sent))
        self.assertEqual(received, sent)

    def test_the_controllers_death_ends_the_writer_while_audio_flows(self):
        self.outputs(LOOPBACK + CLIENT)
        controller = self.controller_process()
        fifo, reader = self.daemon_fifo()
        writer = self.write(fifo)
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        writer.stdin.write(bytes(640))
        writer.stdin.flush()
        controller.kill()
        controller.wait()
        self.assertEqual(writer.wait(timeout=5), 0)
        self.assertFalse((self.directory / mic.WRITER_PID_FILE).exists())

    def test_the_controllers_death_ends_a_writer_held_by_a_full_fifo(self):
        self.outputs(LOOPBACK + CLIENT)
        controller = self.controller_process()
        # The daemon stopped reading: nothing drains the FIFO.
        fifo, _ = self.daemon_fifo()
        writer = self.write(fifo)
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        feeding = threading.Thread(target=self.feed, args=(writer, 1 << 20), daemon=True)
        feeding.start()
        time.sleep(0.5)
        self.assertIsNone(writer.poll(), "the writer ended before the controller did")
        controller.kill()
        controller.wait()
        self.assertEqual(writer.wait(timeout=5), 0)

    def feed(self, writer, size):
        try:
            writer.stdin.write(bytes(size))
            writer.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass


ENTRYPOINT = PROJECT / "container/ko-agent-sandbox/ko-sandbox-entrypoint"
CONFIG = PROJECT / "container/ko-agent-sandbox/microphone/microphone.pa"
# Values the daemon passes through unchanged, so a capture counts each sequence's samples: the
# earlier, which no stream may receive, and the later, which the stream must.
EARLIER, LATER = 1111, 2222


def pcm(values):
    return b"".join(struct.pack("<h", value) for value in values)


def pcm_values(raw):
    return [value for (value,) in struct.iter_unpack("<h", raw[: len(raw) - len(raw) % 2])]


@unittest.skipUnless(shutil.which("pulseaudio") and shutil.which("parecord"), "needs the image's PulseAudio")
class DaemonTest(ReapingTest):
    """The daemon as the entrypoint starts it, from the repository's script, under a temporary
    directory in place of the session's: its own socket and FIFO, beside any session daemon."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ko-sandbox-mic-daemon-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.fifo = self.root / "mic"
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.home),
            "PULSE_CONFIG_PATH": str(self.root / "pulse-config"),
            "PULSE_STATE_PATH": str(self.root / "pulse-state"),
            "PULSE_RUNTIME_PATH": str(self.root / "pulse-runtime"),
            "PULSE_COOKIE": str(self.root / "pulse-config/cookie"),
            "PULSE_SERVER": f"unix:{self.root}/pulse-runtime/native",
        }
        for name in ("pulse-config", "pulse-state", "pulse-runtime"):
            (self.root / name).mkdir(mode=0o700)
        script = self.root / "microphone.pa"
        script.write_text(CONFIG.read_text().replace("/tmp/ko-agent-sandbox/microphone/mic", str(self.fifo)))
        # The entrypoint's command line, its script swapped for the copy above.
        line = re.search(r"^\s*(pulseaudio -n .*?)>>", ENTRYPOINT.read_text().replace("\\\n", " "), re.M)
        command = [
            f"--file={script}" if word.startswith("--file=") else word for word in shlex.split(line.group(1))
        ]
        self.daemon = self.reaped(subprocess.Popen(
            command, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        deadline = time.monotonic() + 10
        while not (self.fifo.exists() and self.pactl("info").returncode == 0):
            self.assertIsNone(self.daemon.poll(), "the daemon exited")
            self.assertLess(time.monotonic(), deadline, "the daemon did not answer")
            time.sleep(0.1)
        self.fifo_writer = os.open(self.fifo, os.O_WRONLY)
        self.addCleanup(os.close, self.fifo_writer)
        self.fifo_burst = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, self.fifo_burst)

    def pactl(self, *arguments):
        return subprocess.run(["pactl", *arguments], env=self.env, capture_output=True)

    def stream(self):
        """A client recording the microphone, as agy's `parec` does."""
        return self.reaped(subprocess.Popen(
            ["parecord", "--raw", "--format=s16le", "--rate=16000", "--channels=1", "--latency-msec=20",
             "--device=fifo_input"],
            env=self.env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ))

    def stopped(self, stream):
        stream.send_signal(signal.SIGINT)
        out, _ = stream.communicate(timeout=10)
        return pcm_values(out)

    def burst(self, value, samples):
        """Up to `samples` samples of `value` at once, as many as the FIFO takes without blocking: a
        paused daemon reads none, and pipe(7) lets a FIFO hold as little as one page."""
        try:
            written = os.write(self.fifo_burst, pcm([value] * samples))
        except BlockingIOError:
            written = 0
        self.assertGreater(written, 0, "the FIFO took no sample")

    def paced(self, value, seconds):
        for _ in range(int(seconds * 50)):
            os.write(self.fifo_writer, pcm([value] * 320))
            time.sleep(0.02)

    def test_the_daemon_keeps_to_its_directories_serves_its_socket_and_loads_no_module(self):
        info = self.pactl("info")
        self.assertIn(b"Default Source: fifo_input", info.stdout)
        refused = self.pactl("load-module", "module-null-sink", "sink_name=other")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(list(self.home.iterdir()), [], "the daemon wrote under HOME")
        cookies = [path for path in self.root.rglob("*cookie*") if path.parent != self.root / "pulse-config"]
        self.assertEqual(cookies, [])

    def test_the_controller_sends_start_for_a_stream_on_the_daemon(self):
        os.mkfifo(self.root / "req")
        requests = os.open(self.root / "req", os.O_RDONLY | os.O_NONBLOCK)
        self.addCleanup(os.close, requests)
        self.reaped(subprocess.Popen(
            [sys.executable, "-I", str(PROGRAM), "control", str(self.root)],
            env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ))
        self.stream()
        deadline = time.monotonic() + 3
        received = b""
        while not received and time.monotonic() < deadline:
            time.sleep(0.05)
            try:
                received = os.read(requests, 64)
            except BlockingIOError:
                pass
        self.assertEqual(received, b"start\n")

    def idle_then_stream(self, delayed):
        """EARLIER written while no stream is open, then a stream opens and LATER is written."""
        if delayed:
            self.daemon.send_signal(signal.SIGSTOP)
        self.burst(EARLIER, 8000)
        stream = self.stream()
        time.sleep(0.3)
        if delayed:
            self.daemon.send_signal(signal.SIGCONT)
        self.paced(LATER, 1)
        time.sleep(0.3)
        return self.stopped(stream)

    def stream_then_stream(self, delayed):
        """The first stream closes and the second opens in quick succession, the tail of EARLIER written
        across the switch, then LATER."""
        first = self.stream()
        time.sleep(0.3)
        self.paced(EARLIER, 0.5)
        if delayed:
            self.daemon.send_signal(signal.SIGSTOP)
        self.burst(EARLIER, 3200)
        first.send_signal(signal.SIGINT)
        second = self.stream()
        if delayed:
            time.sleep(0.3)
            self.daemon.send_signal(signal.SIGCONT)
        first.communicate(timeout=10)
        time.sleep(0.2)
        self.paced(LATER, 1)
        time.sleep(0.3)
        return self.stopped(second)

    def assert_boundary(self, case, delayed):
        try:
            values = case(delayed)
        finally:
            self.daemon.send_signal(signal.SIGCONT)
        # Above zero would be the design's limit to record, not a timing to tune
        # (doc/microphone.md, "The daemon").
        self.assertEqual(values.count(EARLIER), 0, f"{case.__name__}, daemon delayed: {delayed}")
        self.assertGreater(values.count(LATER), 15000, f"{case.__name__}, daemon delayed: {delayed}")

    def test_no_sample_written_before_a_stream_reaches_it(self):
        for case in (self.idle_then_stream, self.stream_then_stream):
            for delayed in (False, True):
                self.assert_boundary(case, delayed)

    def test_no_sample_written_before_a_stream_reaches_it_through_a_one_page_fifo(self):
        fcntl.fcntl(self.fifo_writer, fcntl.F_SETPIPE_SZ, os.sysconf("SC_PAGE_SIZE"))
        for case in (self.idle_then_stream, self.stream_then_stream):
            for delayed in (False, True):
                self.assert_boundary(case, delayed)

    def test_no_sample_written_before_a_stream_reaches_it_under_cpu_load(self):
        load = [
            subprocess.Popen([sys.executable, "-I", "-c", "while True: pass"]) for _ in range(os.cpu_count() * 2)
        ]
        try:
            for case in (self.idle_then_stream, self.stream_then_stream):
                for delayed in (False, True):
                    self.assert_boundary(case, delayed)
        finally:
            for process in load:
                process.kill()
                process.wait()

    def test_audio_through_the_writer_arrives_sample_for_sample_in_odd_fragments(self):
        stream = self.stream()
        controller = self.reaped(subprocess.Popen(["sleep", "60"]))
        (self.root / mic.CONTROLLER_PID_FILE).write_text(f"{controller.pid} {mic.start_time(controller.pid)}\n")
        time.sleep(0.3)
        writer = self.reaped(subprocess.Popen(
            [sys.executable, "-I", str(PROGRAM), "write", str(self.fifo)],
            env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ))
        self.assertEqual(writer.stdout.readline(), b"ready\n")
        # A ramp with no zero, which the daemon's silence between writes cannot be taken for.
        sent = list(range(1, 16001))
        raw = pcm(sent)
        sizes = itertools.cycle((1, 639, 3, 1281, 7, 4095))
        offset = 0
        while offset < len(raw):
            size = next(sizes)
            writer.stdin.write(raw[offset:offset + size])
            writer.stdin.flush()
            offset += size
            time.sleep(0.01)
        writer.stdin.close()
        self.assertEqual(writer.wait(timeout=10), 0)
        time.sleep(0.5)
        received = [value for value in self.stopped(stream) if value != 0]
        self.assertEqual(received, sent)


CLAUDE = Path("/usr/bin/claude")


@unittest.skipUnless(CLAUDE.exists() and Path("/etc/ko-agent-sandbox/microphone.pa").exists(), "needs the image")
class ClaudeCodeRecorderContractTest(unittest.TestCase):
    """What the daemon serves of Claude Code's `/voice` on Linux, read from the image's CLI
    (doc/microphone.md, "Claude Code"): a release that changes it fails here. Its minified names
    change with every build, so the patterns name none of them."""

    @classmethod
    def setUpClass(cls):
        cls.cli = CLAUDE.read_bytes()

    def found(self, pattern, what):
        self.assertIsNotNone(re.search(pattern, self.cli, re.S), what)

    def test_the_cli_records_through_sox_rec_when_arecord_is_absent(self):
        self.found(
            rb'if\(await \w+\("arecord"\)\)\{let \w+=await \w+\(\w+\);if\(\w+\.ok\)return\{available:!0,reason:null\};'
            rb'.{0,80}?\}let (\w+)=await \w+\("sox"\);if\(\1&&await \w+\("rec"\)\)return\{available:!0',
            "arecord before SoX, and SoX available when `sox --version` and `rec --version` succeed",
        )
        self.found(
            rb'async function \w+\(\w+\)\{return\(await \w+\(\w+,\["--version"\],\{timeout:3000',
            "the availability check runs each program's --version",
        )

    def test_rec_records_the_default_device_as_the_daemon_serves_it(self):
        self.found(rb'var \w+=16000,\w+=1,', "16000 Hz, one channel")
        self.found(
            rb'\["-q","--buffer","1024","-t","raw","-r",String\(\w+\),"-e","signed","-b","16","-c",String\(\w+\),"-"\]',
            "rec's arguments: raw signed 16-bit from the default device, in 1024-byte buffers",
        )
        self.found(rb'=\w+\("rec",\w+,\{stdio:\["pipe","pipe","pipe"\]', "rec spawned with those arguments")


if __name__ == "__main__":
    unittest.main()
