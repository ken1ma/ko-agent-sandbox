"""Tests of the ko-review plugin's helper against a fake `codex` on PATH; no model is used."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest


PROJECT = Path(__file__).resolve().parents[3]
PLUGIN = PROJECT / "container/ko-agent-sandbox/claude-code/plugins/ko-review"
HELPER = PLUGIN / "bin/ko-review"

# Steps are consumed one per invocation from the file FAKE_CODEX_SCRIPT names; each invocation
# appends its argv and stdin to FAKE_CODEX_LOG.
FAKE_CODEX = r'''#!/usr/bin/env python3
import json, os, sys, time
if sys.argv[1:] == ["--version"]:
    print("fake-codex 0"); sys.exit(0)
if sys.argv[1:] == ["debug", "models"]:
    if os.environ.get("FAKE_CODEX_NO_CATALOG"):
        sys.exit(1)
    print(json.dumps({"models": [{"slug": "gpt-test", "default_reasoning_level": "medium",
                                  "supported_reasoning_levels": [{"effort": "low"}, {"effort": "high"}]}]}))
    sys.exit(0)
if sys.argv[1:] == ["login", "status"]:
    if os.environ.get("FAKE_CODEX_SIGNED_OUT"):
        print("Not logged in"); sys.exit(1)
    print("Logged in using ChatGPT"); sys.exit(0)
prompt = sys.stdin.read()
script = json.loads(open(os.environ["FAKE_CODEX_SCRIPT"]).read())
step = script.pop(0) if script else {}
open(os.environ["FAKE_CODEX_SCRIPT"], "w").write(json.dumps(script))
with open(os.environ["FAKE_CODEX_LOG"], "a") as log:
    log.write(json.dumps({"argv": sys.argv[1:], "prompt": prompt, "cwd": os.getcwd(), "pid": os.getpid()}) + "\n")
def emit(event):
    # like Codex mid-command, live on when the helper's end of stdout is gone
    try:
        print(json.dumps(event), flush=True)
    except BrokenPipeError:
        pass
args = sys.argv[1:]
resume_id = args[args.index("resume") + 1] if "resume" in args else None
thread_id = step.get("thread_id", resume_id or "thread-" + str(len(open(os.environ["FAKE_CODEX_LOG"]).readlines())))
if step.get("touch"):
    open(step["touch"], "a").write("changed during review\n")
if "raw_stdout" in step:
    sys.stdout.write(step["raw_stdout"])
    sys.stdout.flush()
else:
    if step.get("emit_thread_started", True):
        emit({"type": "thread.started", "thread_id": thread_id})
    time.sleep(step.get("sleep", 0))
    emit({"type": "turn.started"})
    for event in step.get("events", []):
        emit(event)
    if "result" in step and step["result"] is not None:
        result = step["result"]
        text = result if isinstance(result, str) else json.dumps(result)
        emit({"type": "item.completed", "item": {"type": "agent_message", "text": text}})
        open(args[args.index("--output-last-message") + 1], "w").write(text)
    emit({"type": "turn.completed"})
sys.stderr.write(step.get("stderr", ""))
if os.environ.get("FAKE_CODEX_DONE"):
    open(os.environ["FAKE_CODEX_DONE"], "w").write("ran to the end\n")
sys.exit(step.get("exit", 0))
'''

CHANGES = {
    "disposition": "CHANGES_REQUESTED", "summary": "one issue",
    "findings": [{"id": "F1", "severity": "high", "location": "app.py:1", "description": "d", "evidence": "e"}],
    "userDecision": None,
}
APPROVED = {"disposition": "APPROVED", "summary": "fine", "findings": [], "userDecision": None}
USER_DECIDES = {
    "disposition": "USER_DECISION_REQUIRED", "summary": "needs a call", "findings": [],
    "userDecision": {
        "issue": "i", "codexPosition": "p", "whyTechnicalEvidenceCannotDecide": "w", "decisionRequested": "d",
    },
}


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ko-review-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "codex"
        fake.write_text(FAKE_CODEX)
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.script = self.root / "script.json"
        self.log = self.root / "log.jsonl"
        self.script.write_text("[]")
        self.log.write_text("")
        self.state = self.root / "state"
        self.ruleset = "egress profile: deny-unless-allowed\nallow https://api.openai.com/ tunnel\n"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write("app.py", "print('hi')\n")
        self.write(".gitignore", "ignored/\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "init")
        self.write("work.py", "print('work in progress')\n")  # something to review: a clean tree is refused

    def git(self, *args):
        return subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "core.symlinks=true", *args],
            cwd=self.repo, capture_output=True, text=True, check=True,
        )

    def write(self, relative, content):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def message(self, text="## Task\n\nreview me\n"):
        path = self.root / f"message-{len(list(self.root.iterdir()))}.md"
        path.write_text(text)
        return str(path)

    def plan(self, *steps):
        self.script.write_text(json.dumps(list(steps)))

    environment = {}

    def helper(self, *args, cwd=None, expect=0):
        process = self.spawn(*args, cwd=cwd)
        stdout, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, expect, stdout + stderr)
        return json.loads(stdout)

    def spawn(self, *args, cwd=None):
        environment = self.environment
        return subprocess.Popen(
            [sys.executable, "-I", str(HELPER), *args],
            cwd=cwd or self.repo, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={
                **{name: value for name, value in os.environ.items() if not name.startswith("KO_")},
                "PATH": f"{self.bin}:{os.environ['PATH']}",
                "FAKE_CODEX_SCRIPT": str(self.script),
                "FAKE_CODEX_LOG": str(self.log),
                "KO_REVIEW_STATE": str(self.state),
                "KO_AGENT_SANDBOX_EGRESS_RULESET": self.ruleset,
                **environment,
            },
        )

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]

    def state_of(self, review_id):
        return json.loads(Path(self.helper("show", review_id)["statePath"]).read_text())

    def journal_of(self, review_id):
        path = Path(self.helper("show", review_id)["journalPath"])
        return [json.loads(line) for line in path.read_text().splitlines()]

    def start(self, result=CHANGES, **step):
        self.plan({"result": result, **step})
        return self.helper("start", "codex", "--message-file", self.message())

    def test_start_opens_a_thread_and_records_the_round(self):
        output = self.start()
        self.assertEqual(output["disposition"], "CHANGES_REQUESTED")
        self.assertEqual(output["status"], "CHANGES_REQUESTED")
        self.assertEqual(output["round"], 1)
        self.assertEqual(output["findings"][0]["id"], "F1")
        state = self.state_of(output["reviewId"])
        self.assertEqual(state["codexThreadId"], "thread-1")
        self.assertEqual(state["lastReviewed"]["worktreeDigest"], output["currentWorktreeDigest"])
        self.assertIsNone(state["approved"])
        call = self.calls()[0]
        self.assertEqual(call["argv"][:2], ["exec", "--json"])
        self.assertNotIn("resume", call["argv"])
        self.assertNotIn("--ephemeral", call["argv"])
        schema = call["argv"][call["argv"].index("--output-schema") + 1]
        self.assertEqual(schema, str(PLUGIN / "schemas/review-result.schema.json"))
        self.assertEqual(Path(call["cwd"]).resolve(), self.repo.resolve())
        self.assertIn("You are an independent code reviewer", call["prompt"])
        self.assertIn("review me", call["prompt"])
        rounds = Path(state["reviewId"] and output["statePath"]).parent / "rounds"
        self.assertEqual(sorted(path.name for path in rounds.iterdir()),
                         ["001-codex.jsonl", "001-codex.stderr", "001-input.md", "001-manifest.json",
                          "001-result.json"])
        kinds = [(entry["seq"], entry["actor"], entry["kind"]) for entry in self.journal_of(output["reviewId"])]
        self.assertEqual(kinds, [(1, "author", "review-request"), (2, "codex", "review-result")])
        listed = self.helper("list")["reviews"]
        self.assertEqual([review["reviewId"] for review in listed], [output["reviewId"]])
        repository = json.loads(next(self.state.glob("repositories/*/repository.json")).read_text())
        self.assertEqual(Path(repository["repository"]).resolve(), self.repo.resolve())

    def test_continue_resumes_the_same_thread_and_approval_binds_the_tree(self):
        review_id = self.start()["reviewId"]
        self.helper("verify", review_id, expect=1)
        self.write("app.py", "print('fixed')\n")
        self.plan({"result": APPROVED})
        response = self.message("## Accepted findings\n\nF1 fixed\n")
        output = self.helper("continue", review_id, "--message-file", response)
        self.assertEqual(output["status"], "APPROVED")
        self.assertEqual(output["round"], 2)
        self.assertTrue(output["approvalFresh"])
        call = self.calls()[1]
        self.assertEqual(call["argv"][:3], ["exec", "resume", "thread-1"])
        self.assertIn("F1 fixed", call["prompt"])
        self.assertIn("The author responded to your previous review", call["prompt"])
        verified = self.helper("verify", review_id)
        self.assertEqual(verified["effectiveStatus"], "APPROVED")
        self.git("add", "-A")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")  # staged, as approved
        self.git("commit", "-q", "-m", "the reviewed changes")  # the tree is the approved one; only HEAD moved
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        self.write("app.py", "print('staged, unreviewed')\n")
        self.git("add", "app.py")
        self.write("app.py", "print('fixed')\n")  # the working tree is back at the approved content
        staged = self.helper("verify", review_id, expect=1)["error"]
        self.assertEqual(staged["effectiveStatus"], "STALE_APPROVAL")
        self.git("reset", "-q", "app.py")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        self.write("app.py", "print('edited after approval')\n")
        stale = self.helper("verify", review_id, expect=1)["error"]
        self.assertEqual(stale["code"], "NOT_APPROVED")
        self.assertEqual(stale["effectiveStatus"], "STALE_APPROVAL")
        self.assertFalse(self.helper("show", review_id)["approvalFresh"])
        self.plan({"result": APPROVED})
        again = self.helper("continue", review_id, "--message-file", self.message())
        self.assertEqual(again["round"], 3)
        self.assertTrue(again["approvalFresh"])

    def test_resumed_thread_must_be_the_persisted_one(self):
        review_id = self.start()["reviewId"]
        self.plan({"result": APPROVED, "thread_id": "thread-other"})
        error = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "CODEX_RESUME_MISMATCH")
        self.assertEqual((error["expected"], error["actual"]), ("thread-1", "thread-other"))
        state = self.state_of(review_id)
        self.assertEqual(state["status"], "CHANGES_REQUESTED")
        self.assertEqual(state["codexThreadId"], "thread-1")
        self.assertEqual(state["lastError"]["code"], "CODEX_RESUME_MISMATCH")
        self.assertEqual(state["lastError"]["round"], 2)
        self.assertEqual(self.journal_of(review_id)[-1]["kind"], "error")
        self.plan({"result": APPROVED})
        self.assertEqual(self.helper("continue", review_id, "--message-file", self.message())["round"], 3)

    def test_failures_are_errors_never_dispositions(self):
        cases = [
            ({"raw_stdout": "not json\n"}, "INVALID_RESULT"),
            ({"result": "{not json"}, "INVALID_RESULT"),
            ({"result": {**CHANGES, "disposition": "MAYBE"}}, "INVALID_RESULT"),
            ({"result": {**CHANGES, "disposition": []}}, "INVALID_RESULT"),
            ({"result": {**CHANGES, "findings": [{**CHANGES["findings"][0], "severity": {}}]}},
             "INVALID_RESULT"),
            ({"result": {**APPROVED, "findings": CHANGES["findings"]}}, "INVALID_RESULT"),
            ({"result": {**USER_DECIDES, "userDecision": None}}, "INVALID_RESULT"),
            ({"result": {**CHANGES, "userDecision": USER_DECIDES["userDecision"]}}, "INVALID_RESULT"),
            ({"result": {key: value for key, value in APPROVED.items() if key != "userDecision"}}, "INVALID_RESULT"),
            ({"result": {**APPROVED, "extra": 1}}, "INVALID_RESULT"),
            ({"result": {**CHANGES, "findings": [{"id": "F1", "severity": "low", "description": "d"}]}},
             "INVALID_RESULT"),
            ({"result": {**CHANGES, "findings": [{**CHANGES["findings"][0], "location": 3}]}}, "INVALID_RESULT"),
            ({"result": {**USER_DECIDES, "userDecision": {**USER_DECIDES["userDecision"], "more": "x"}}},
             "INVALID_RESULT"),
            ({"result": None}, "INVALID_RESULT"),
            ({"exit": 1, "emit_thread_started": False, "stderr": "boom"}, "CODEX_FAILED"),
            ({"exit": 1, "result": APPROVED, "stderr": "boom"}, "CODEX_FAILED"),
            ({"emit_thread_started": False, "result": APPROVED}, "CODEX_FAILED"),
            ({"events": [{"type": "turn.failed", "error": {"message": "model overloaded"}}]}, "CODEX_FAILED"),
            ({"exit": 1, "stderr": "Error: thread/resume failed: no rollout found for thread id x"}, "CODEX_FAILED"),
            ({"exit": 1, "stderr": "Not logged in. Run codex login."}, "CODEX_AUTH_FAILED"),
            ({"exit": 1, "stderr": "error sending request: 403 Forbidden from proxy"}, "CODEX_EGRESS_DENIED"),
        ]
        for step, code in cases:
            with self.subTest(step=step):
                self.plan(step)
                error = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"]
                self.assertEqual(error["code"], code, error)
        for review in self.helper("list")["reviews"]:
            self.assertEqual(review["status"], "NEW")
            self.assertIsNone(review["approved"])
            self.assertEqual(review["lastError"]["round"], 1)
            self.assertEqual(self.helper("verify", review["reviewId"], expect=1)["error"]["code"], "NOT_APPROVED")

    def test_tree_change_during_a_turn_discards_the_result(self):
        self.plan({"result": APPROVED, "touch": "app.py"})
        error = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "WORKTREE_CHANGED_DURING_REVIEW")
        self.assertNotEqual(error["before"], error["after"])
        self.assertEqual(error["paths"], ["app.py"])
        review = self.helper("list")["reviews"][0]
        self.assertEqual(review["status"], "NEW")
        self.assertIsNone(review["approved"])
        self.assertEqual(review["codexThreadId"], "thread-1")
        self.assertIn("changed during review", (self.repo / "app.py").read_text())
        self.plan({"result": APPROVED})
        retried = self.helper("continue", review["reviewId"], "--message-file", self.message("again\n"))
        self.assertEqual((retried["status"], retried["round"]), ("APPROVED", 2))
        call = self.calls()[1]
        self.assertEqual(call["argv"][:3], ["exec", "resume", "thread-1"])
        self.assertIn("You are an independent code reviewer", call["prompt"])

    def test_a_thread_named_before_an_interrupted_or_truncated_turn_is_kept(self):
        started = json.dumps({"type": "thread.started", "thread_id": "kept"}) + "\n"
        cases = [
            ("timeout", {"result": APPROVED, "sleep": 5}, ("--timeout", "1"), "TURN_INTERRUPTED"),
            ("truncated", {"raw_stdout": started + '{"type": "turn.sta'}, (), "INVALID_RESULT"),
            ("failed after start", {"raw_stdout": started, "exit": 1, "stderr": "boom"}, (), "CODEX_FAILED"),
        ]
        for label, step, options, code in cases:
            with self.subTest(label):
                self.plan(step, {"result": APPROVED})
                error = self.helper("start", "codex", *options, "--message-file", self.message(), expect=1)["error"]
                self.assertEqual(error["code"], code, error)
                review = self.helper("list")["reviews"][-1]
                self.assertEqual(review["status"], "NEW")
                self.assertEqual(review["codexThreadId"], "kept" if label != "timeout" else "thread-1")
                retried = self.helper("continue", review["reviewId"], "--message-file", self.message())
                self.assertEqual(retried["status"], "APPROVED")
                self.assertEqual(self.calls()[-1]["argv"][:3], ["exec", "resume", review["codexThreadId"]])
                self.log.write_text("")

    def test_a_helper_failure_while_codex_runs_kills_codex_before_the_lock_is_released(self):
        review_id = self.start()["reviewId"]
        rounds = Path(self.helper("show", review_id)["statePath"]).parent / "rounds"
        (rounds / "002-codex.jsonl").mkdir()  # the event log cannot be opened once Codex has started
        self.plan({"result": APPROVED, "sleep": 2}, {"result": APPROVED})
        done = self.root / "codex-ran-to-the-end"
        self.environment = {"FAKE_CODEX_DONE": str(done)}
        error = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.environment = {}
        self.assertEqual(error["code"], "HELPER_FAILED", error)
        self.assertIn("IsADirectoryError", error["message"])
        threading.Event().wait(3)  # past the fake's sleep: an orphaned Codex would have written the marker
        self.assertFalse(done.exists(), "codex outlived the helper")
        state = self.helper("show", review_id)
        self.assertEqual((state["status"], state["lastError"]["code"]), ("CHANGES_REQUESTED", "HELPER_FAILED"))
        (rounds / "002-codex.jsonl").rmdir()
        continued = self.helper("continue", review_id, "--message-file", self.message())
        self.assertEqual(continued["status"], "APPROVED")

    def test_terminating_the_helper_kills_codex_and_keeps_the_thread(self):
        import signal
        self.plan({"result": APPROVED, "sleep": 4}, {"result": APPROVED})
        done = self.root / "codex-ran-to-the-end"
        self.environment = {"FAKE_CODEX_DONE": str(done)}
        process = self.spawn("start", "codex", "--message-file", self.message())
        self.environment = {}
        for _ in range(100):  # until the fake has named its thread
            reviews = self.helper("list")["reviews"]
            if reviews and reviews[0]["codexThreadId"]:
                break
            threading.Event().wait(0.1)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=30)
        self.assertEqual(process.returncode, 1, stdout + stderr)
        error = json.loads(stdout)["error"]
        self.assertEqual((error["code"], error["message"]), ("TURN_INTERRUPTED", "terminated by SIGTERM"))
        threading.Event().wait(5)  # past the fake's sleep: an orphaned Codex would have written the marker
        self.assertFalse(done.exists(), "codex outlived the helper")
        review = self.helper("list")["reviews"][0]
        self.assertEqual((review["status"], review["codexThreadId"]), ("NEW", "thread-1"))
        self.assertEqual(review["lastError"]["code"], "TURN_INTERRUPTED")
        retried = self.helper("continue", review["reviewId"], "--message-file", self.message())
        self.assertEqual(retried["status"], "APPROVED")
        self.assertEqual(self.calls()[-1]["argv"][:3], ["exec", "resume", "thread-1"])

    def test_termination_while_the_snapshot_is_taken_stops_before_codex(self):
        import shutil
        import signal
        real_git = shutil.which("git")
        wrapper = self.bin / "git"
        wrapper.write_text("\n".join([
            "#!/usr/bin/env python3",
            "import os, sys, time",
            'if sys.argv[1:2] == ["update-ref"]:',
            '    open(os.environ["FAKE_GIT_MARKER"], "w").write("in update-ref")',
            "    time.sleep(5)",
            f'os.execv({real_git!r}, ["git", *sys.argv[1:]])',
        ]) + "\n")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        marker = self.root / "git-marker"
        self.environment = {"FAKE_GIT_MARKER": str(marker)}
        self.plan({"result": APPROVED})
        process = self.spawn("start", "codex", "--message-file", self.message())
        for _ in range(100):
            if marker.exists():
                break
            threading.Event().wait(0.1)
        self.assertTrue(marker.exists())
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=30)
        self.environment = {}
        wrapper.unlink()
        self.assertEqual(process.returncode, 1, stdout + stderr)
        output = json.loads(stdout)
        self.assertEqual(output["error"]["code"], "TURN_INTERRUPTED")
        self.assertEqual(self.calls(), [])
        review = self.helper("show", output["reviewId"])
        self.assertEqual((review["status"], review["lastError"]["code"]), ("NEW", "TURN_INTERRUPTED"))
        self.assertEqual(self.git_out("for-each-ref", f"refs/ko-review/{output['reviewId']}/"), "")

    def test_model_and_effort_reach_every_codex_command(self):
        self.plan({"result": CHANGES}, {"result": APPROVED})
        output = self.helper("start", "codex", "--model", "gpt-test", "--effort", "high",
                             "--message-file", self.message())
        self.assertEqual((output["codexModel"], output["codexEffort"]), ("gpt-test", "high"))
        self.helper("continue", output["reviewId"], "--message-file", self.message())
        for call in self.calls():
            argv = call["argv"]
            self.assertEqual(argv[argv.index("--model") + 1], "gpt-test")
            self.assertEqual(argv[argv.index("-c") + 1], 'model_reasoning_effort="high"')
        self.start()
        self.assertNotIn("--model", self.calls()[-1]["argv"])
        self.assertNotIn("-c", self.calls()[-1]["argv"])

    def test_defaults_follow_codex_precedence_for_this_repository(self):
        home = self.root / "codex-home"
        home.mkdir()
        self.environment = {"CODEX_HOME": str(home)}
        found = self.helper("defaults", "codex")
        self.assertEqual((found["model"], found["partial"]), (None, True))
        self.assertEqual(found["catalog"],
                         [{"model": "gpt-test", "defaultEffort": "medium", "efforts": ["low", "high"]}])
        self.assertEqual(found["recommended"], {"model": None, "effort": None, "efforts": None})
        (home / "config.toml").write_text('model = "gpt-test"\n')  # effort from the catalog's default
        self.assertEqual(self.helper("defaults", "codex")["recommended"],
                         {"model": "gpt-test", "effort": "medium", "efforts": ["low", "high"]})
        self.environment = {"CODEX_HOME": str(home), "FAKE_CODEX_NO_CATALOG": "1"}
        found = self.helper("defaults", "codex")
        self.assertIsNone(found["catalog"])
        self.assertEqual(found["recommended"], {"model": "gpt-test", "effort": None, "efforts": None})
        self.environment = {"CODEX_HOME": str(home)}
        (home / "config.toml").write_text('model = "gpt-user"\nmodel_reasoning_effort = "high"\n[tui]\nx = 1\n')
        self.write(".codex/config.toml", 'model = "gpt-project"\n')
        found = self.helper("defaults", "codex")  # the project is not trusted: its file is skipped
        self.assertEqual((found["model"], found["effort"]), ("gpt-user", "high"))
        self.assertEqual(found["source"]["model"], str(home / "config.toml"))
        (home / "config.toml").write_text(
            'model = "gpt-user"\nmodel_reasoning_effort = "high"\n'
            f'[projects."{self.repo.resolve()}"]\ntrust_level = "trusted"\n'
        )
        found = self.helper("defaults", "codex")
        self.assertEqual((found["model"], found["effort"]), ("gpt-project", "high"))
        self.assertEqual(found["source"],
                         {"model": str(self.repo / ".codex/config.toml"), "effort": str(home / "config.toml")})
        (home / "config.toml").write_text("model = [not toml\n")
        self.assertEqual(self.helper("defaults", "codex", expect=1)["error"]["code"], "CODEX_CONFIG_UNREADABLE")
        self.environment = {}

    def filtered_repository(self, directory):
        """A repository whose `conf` file has a clean filter stripping `local` and `changed` lines."""
        run = lambda *args: subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(directory), *args],
            check=True, capture_output=True,
        )
        (directory / ".gitattributes").write_text("conf filter=strip\n")
        run("config", "filter.strip.clean", "sed -e /^local/d -e /^changed/d")
        (directory / "conf").write_text("keep\nlocal one\n")
        run("add", ".gitattributes", "conf")
        run("commit", "-q", "-m", "filtered file")
        return run

    def test_a_clean_filter_cannot_hide_a_change(self):
        self.filtered_repository(self.repo)
        inner = self.repo / "inner"
        inner.mkdir()
        subprocess.run(["git", "init", "-q", str(inner)], check=True)
        self.filtered_repository(inner)
        review_id = self.start(APPROVED)["reviewId"]
        self.write("conf", "keep\nlocal two\n")  # the filtered blob is unchanged; the file is not
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["effectiveStatus"], "STALE_APPROVAL")
        self.write("conf", "keep\nlocal one\n")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        (inner / "conf").write_text("keep\nlocal two\n")  # the same inside a nested repository
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["effectiveStatus"], "STALE_APPROVAL")
        (inner / "conf").write_text("keep\nlocal one\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "after approval")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        self.write("conf", "keep\nlocal two\n")
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["effectiveStatus"], "STALE_APPROVAL")
        self.write("conf", "keep\nlocal one\n")
        self.plan({"result": APPROVED, "touch": "conf"})  # appends a line the filter strips
        error = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "WORKTREE_CHANGED_DURING_REVIEW")

    def test_an_approved_deletion_or_rename_survives_staging_and_committing(self):
        self.write("gone.txt", "to be deleted\n")
        self.write("old.txt", "to be renamed\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "two files")
        (self.repo / "gone.txt").unlink()
        (self.repo / "old.txt").rename(self.repo / "new.txt")
        review_id = self.start(APPROVED)["reviewId"]
        self.git("add", "-A")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        self.git("commit", "-q", "-m", "deletion and rename")
        self.assertEqual(self.helper("verify", review_id)["effectiveStatus"], "APPROVED")
        self.write("gone.txt", "back\n")
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["effectiveStatus"], "STALE_APPROVAL")

    def test_a_first_turn_that_dies_before_a_thread_is_retried_on_a_new_thread(self):
        self.plan({"exit": 1, "emit_thread_started": False, "stderr": "boom"}, {"result": APPROVED})
        review_id = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"] and \
            self.helper("list")["reviews"][0]["reviewId"]
        self.assertIsNone(self.helper("show", review_id)["codexThreadId"])
        retried = self.helper("continue", review_id, "--message-file", self.message())
        self.assertEqual((retried["status"], retried["codexThreadId"]), ("APPROVED", "thread-2"))
        self.assertNotIn("resume", self.calls()[1]["argv"])

    def test_concurrent_commands_on_one_review_are_refused(self):
        review_id = self.start()["reviewId"]
        self.plan({"result": APPROVED, "sleep": 3}, {"result": APPROVED})
        outputs = {}

        def slow():
            outputs["slow"] = self.helper("continue", review_id, "--message-file", self.message("slow\n"))

        thread = threading.Thread(target=slow)
        thread.start()
        for _ in range(50):
            if self.log.read_text().count("\n") >= 2:
                break
            threading.Event().wait(0.1)
        busy = self.helper("continue", review_id, "--message-file", self.message("fast\n"), expect=1)["error"]
        self.assertEqual(busy["code"], "REVIEW_BUSY")
        shown = self.helper("show", review_id)
        self.assertEqual(shown["status"], "REVIEWING")
        activity = shown["activity"]
        self.assertEqual(activity["round"], 2)
        self.assertTrue(activity["eventsPath"].endswith("002-codex.jsonl"))
        self.assertGreaterEqual(activity["elapsedSeconds"], 0)
        self.assertEqual(activity["lastEventReceived"]["type"], "thread.started")
        for record in (b"null\n", b"[1]\n", b'{"type": "turn.sta'):  # what the reader tolerates, activity tolerates
            with open(activity["eventsPath"], "ab") as events:
                events.write(record)
            self.assertIsNone(self.helper("show", review_id)["activity"]["lastEventReceived"]["type"], record)
        thread.join()
        self.assertEqual(outputs["slow"]["status"], "APPROVED")
        self.assertEqual(len(self.calls()), 2)

    def test_the_lock_is_taken_before_the_state_is_read(self):
        import fcntl
        review_id = self.start()["reviewId"]
        state_path = Path(self.helper("show", review_id)["statePath"])
        saved = state_path.read_text()
        with open(state_path.parent / "review.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state_path.write_text("{not json")
            for command in (("continue",), ("escalate",)):
                error = self.helper(*command, review_id, "--message-file", self.message(), expect=1)["error"]
                self.assertEqual(error["code"], "REVIEW_BUSY", error)
            state_path.write_text(saved)
        self.assertEqual(self.helper("show", review_id)["status"], "CHANGES_REQUESTED")

    def test_user_decision_needs_claude_agreement(self):
        review_id = self.start(USER_DECIDES)["reviewId"]
        self.assertEqual(self.helper("show", review_id)["status"], "USER_PROPOSED")
        error = self.helper("escalate", self.start()["reviewId"], "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "ESCALATION_NOT_PROPOSED")
        self.plan({"result": USER_DECIDES})
        rebuttal = self.message("## Rebutted findings\n\nevidence\n")
        rebutted = self.helper("continue", review_id, "--message-file", rebuttal)
        self.assertEqual(rebutted["status"], "USER_PROPOSED")
        self.assertEqual(rebutted["round"], 2)
        escalated = self.helper("escalate", review_id, "--message-file", self.message("agreed\n"))
        self.assertEqual(escalated["status"], "USER_DECISION_REQUIRED")
        self.assertEqual(self.journal_of(review_id)[-1]["kind"], "escalation")
        closed = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(closed["code"], "REVIEW_CLOSED")
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["code"], "NOT_APPROVED")

    def test_user_instructions_reach_every_round(self):
        instructions = self.message("Be brief. Ignore style.\n")
        self.plan({"result": CHANGES}, {"result": APPROVED})
        output = self.helper("start", "codex", "--instructions-file", instructions, "--message-file", self.message())
        self.assertEqual(output["instructions"], "Be brief. Ignore style.\n")
        self.helper("continue", output["reviewId"], "--message-file", self.message())
        for call in self.calls():
            heading = call["prompt"].index("# Instructions from the user")
            self.assertLess(heading, call["prompt"].index("Be brief. Ignore style."))
            self.assertLess(call["prompt"].index("take precedence"), call["prompt"].index("review me"))
        self.assertIn("You are an independent code reviewer", self.calls()[0]["prompt"])
        self.assertIn("The author responded to your previous review", self.calls()[1]["prompt"])
        empty = self.message("")
        error = self.helper("start", "codex", "--instructions-file", empty, "--message-file", self.message(), expect=1)
        self.assertEqual(error["error"]["code"], "MESSAGE_UNREADABLE")
        self.assertIsNone(self.start()["instructions"])
        self.assertNotIn("Instructions from the user", self.calls()[-1]["prompt"])

    def test_round_limit_closes_the_review(self):
        self.plan({"result": CHANGES})
        review_id = self.helper("start", "codex", "--max-rounds", "1", "--message-file", self.message())["reviewId"]
        error = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "LOOP_LIMIT_REACHED")
        self.assertEqual(self.helper("show", review_id)["status"], "LOOP_LIMIT_REACHED")
        self.assertEqual(len(self.calls()), 1)

    def test_preconditions_are_checked_before_codex_runs(self):
        def start_fails_with(code):
            error = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"]
            self.assertEqual(error["code"], code, error)

        self.environment = {"FAKE_CODEX_SIGNED_OUT": "1"}
        start_fails_with("CODEX_AUTH_FAILED")
        self.environment = {}
        self.ruleset = "egress profile: deny-unless-model\nallow https://api.anthropic.com/ tunnel\n"
        start_fails_with("CODEX_EGRESS_DENIED")
        self.ruleset = ""
        self.plan({"result": APPROVED})
        self.assertEqual(self.helper("start", "codex", "--message-file", self.message())["status"], "APPROVED")
        self.assertEqual(len(self.calls()), 1)
        empty = self.message("")
        unreadable = self.helper("start", "codex", "--message-file", empty, expect=1)["error"]
        self.assertEqual(unreadable["code"], "MESSAGE_UNREADABLE")
        self.assertEqual(self.helper("show", "no-such-review", expect=1)["error"]["code"], "UNKNOWN_REVIEW")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "program.py").write_text("print('review me')\n")
        error = self.helper("start", "codex", "--message-file", self.message(), cwd=outside, expect=1)["error"]
        self.assertEqual(error["code"], "NOT_A_GIT_REPOSITORY")
        steps = [line for line in error["message"].splitlines() if line.startswith("git ")]
        self.assertEqual(steps, ["git init", 'git commit --allow-empty -m "Start of the review"'])
        import shlex
        for step in steps:  # following the instructions leaves the files in the review's scope
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(outside),
                            *shlex.split(step)[1:]], check=True, capture_output=True)
        self.plan({"result": APPROVED})
        recovered = self.helper("start", "codex", "--message-file", self.message(), cwd=outside)
        self.assertEqual(recovered["status"], "APPROVED")
        self.assertIn("`git diff HEAD` plus untracked files", self.calls()[-1]["prompt"])
        listed = subprocess.run(["git", "-C", str(outside), "ls-tree", "--name-only", recovered["snapshots"][0]["ref"]],
                                capture_output=True, text=True)
        self.assertEqual(listed.stdout.split(), ["program.py"])

    def test_state_is_namespaced_by_checkout(self):
        review_id = self.start(APPROVED)["reviewId"]
        other = self.root / "other"
        subprocess.run(["git", "clone", "-q", str(self.repo), str(other)], check=True, capture_output=True)
        self.assertEqual(self.helper("list", cwd=other)["reviews"], [])
        self.assertEqual(self.helper("show", review_id, cwd=other, expect=1)["error"]["code"], "UNKNOWN_REVIEW")
        self.assertEqual(len(list(self.state.glob("repositories/*"))), 2)

    def digest(self):
        return self.helper("digest")["worktreeDigest"]

    def test_digest_covers_every_kind_of_change(self):
        clean = self.digest()
        self.assertEqual(self.digest(), clean)
        seen = {clean}

        def changed(label):
            digest = self.digest()
            self.assertNotIn(digest, seen, label)
            seen.add(digest)
            return digest

        self.write("app.py", "print('unstaged')\n")
        changed("unstaged edit")
        self.git("add", "app.py")
        changed("staged edit")
        self.write("app.py", "print('staged and unstaged')\n")
        changed("staged plus unstaged")
        self.git("restore", "--source=HEAD", "--worktree", "app.py")
        changed("staged edit with the tree back at HEAD")
        self.git("reset", "-q", "--hard")
        self.assertEqual(self.digest(), clean)
        (self.repo / "app.py").unlink()
        changed("deletion")
        self.git("checkout", "--", "app.py")
        self.git("mv", "app.py", "moved.py")
        changed("rename")
        self.git("reset", "-q", "--hard")
        self.write("untracked.txt", "new\n")
        changed("untracked file")
        (self.repo / "untracked.txt").write_bytes(b"\x00\x01\x02")
        changed("binary content")
        (self.repo / "untracked.txt").chmod(0o755)
        changed("mode")
        (self.repo / "untracked.txt").unlink()
        self.assertEqual(self.digest(), clean)
        self.write("ignored/file", "ignored\n")
        self.assertEqual(self.digest(), clean)
        os.symlink("app.py", self.repo / "link")
        changed("symlink")
        os.unlink(self.repo / "link")
        os.symlink("elsewhere", self.repo / "link")
        changed("symlink target")
        os.unlink(self.repo / "link")
        self.write("ユニコード.txt", "unicode\n")
        changed("unicode name")
        (self.repo / "ユニコード.txt").unlink()
        self.write("new\nline.txt", "newline\n")
        changed("newline in name")
        (self.repo / "new\nline.txt").unlink()
        (self.repo / "empty").mkdir()
        self.assertEqual(self.digest(), clean)
        nested = self.repo / "nested"
        nested.mkdir()
        subprocess.run(["git", "init", "-q", str(nested)], check=True)
        (nested / "inner.txt").write_text("one\n")
        changed("nested repository")
        (nested / "inner.txt").write_text("two\n")
        changed("nested repository content")
        import shutil
        shutil.rmtree(nested)
        self.assertEqual(self.digest(), clean)
        self.write("app.py", "print('committed')\n")
        self.git("commit", "-q", "-am", "next")
        changed("new HEAD")

    def test_digest_follows_a_submodule_past_its_dirty_flags(self):
        library = self.root / "library"
        library.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(library)], check=True)
        (library / "lib.py").write_text("v1\n")
        for args in (("add", "-A"), ("commit", "-q", "-m", "v1")):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(library), *args],
                           check=True, capture_output=True)
        self.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(library), "vendor")
        self.git("commit", "-q", "-m", "add submodule")
        clean = self.digest()
        self.assertEqual(self.start(APPROVED)["snapshots"][0]["excludes"], ["vendor"])  # while clean
        vendor = self.repo / "vendor"
        (vendor / "lib.py").write_text("edited once\n")
        once = self.digest()
        self.assertNotEqual(once, clean)
        (vendor / "lib.py").write_text("edited twice\n")
        twice = self.digest()
        self.assertNotIn(twice, {clean, once})
        for message in ("c1", "c2"):
            (vendor / "lib.py").write_text(message + "\n")
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(vendor),
                            "commit", "-q", "-am", message], check=True, capture_output=True)
            committed = self.digest()
            self.assertNotIn(committed, {clean, once, twice})
            twice = committed

    def git_out(self, *args):
        return self.git(*args).stdout

    def test_each_round_is_snapshotted_under_a_ref_without_touching_the_checkout(self):
        self.write("ignored/tracked", "tracked though ignored\n")
        self.write("ignored/removed", "removed from the index\n")
        self.git("add", "-f", "ignored/tracked", "ignored/removed")
        self.git("commit", "-q", "-m", "force-added")
        self.git("rm", "-q", "--cached", "ignored/removed")
        self.write("ignored/tracked", "tracked though ignored, edited\n")
        self.write("ignored/staged", "staged, not committed\n")
        self.git("add", "-f", "ignored/staged")
        self.write("app.py", "print('changed')\n")
        self.write("untracked.txt", "new\n")
        self.write("ignored/file", "ignored\n")
        status_before = self.git_out("status", "--porcelain=v2", "--untracked-files=all")
        index_before = self.git_out("diff", "--cached", "--stat")
        self.plan({"result": CHANGES}, {"result": APPROVED})
        output = self.helper("start", "codex", "--message-file", self.message())
        review_id = output["reviewId"]
        ref = f"refs/ko-review/{review_id}/round-001"
        self.assertEqual(output["snapshots"][0]["ref"], ref)
        self.assertEqual(output["snapshots"][0]["tree"], output["lastReviewed"]["tree"])
        self.assertEqual(self.git_out("cat-file", "-t", ref).strip(), "tag")
        self.assertEqual(self.git_out("rev-parse", ref + "^{tree}").strip(), output["lastReviewed"]["tree"])
        shown = self.git_out("show", ref)
        self.assertIn(f"# Review {review_id}, round 1", shown)
        self.assertIn("review me", shown)
        self.assertIn("### Codex: CHANGES_REQUESTED", shown)
        self.assertIn("- **F1** (high) `app.py:1`: d", shown)
        self.assertNotIn("## Round", shown)
        self.assertEqual(self.git_out("tag", "--list"), "")
        self.assertRegex(review_id, r"^\d{4}-\d{2}-\d{2}-\d{4}-[0-9a-f]{8}$")
        self.assertEqual(self.git_out("status", "--porcelain=v2", "--untracked-files=all"), status_before)
        self.assertEqual(self.git_out("diff", "--cached", "--stat"), index_before)
        self.assertEqual(self.git_out("branch", "--list").split(), ["*", "main"])
        files = self.git_out("ls-tree", "-r", "--name-only", ref).split("\n")
        self.assertIn("untracked.txt", files)
        self.assertNotIn("ignored/file", files)
        self.assertNotIn("ignored/removed", files)
        self.assertIn("ignored/staged", files)
        self.assertIn("ignored/tracked", files)
        self.assertEqual(self.git_out("show", ref + ":ignored/tracked"), "tracked though ignored, edited\n")
        self.assertEqual(self.git_out("show", ref + ":app.py"), "print('changed')\n")
        self.write("app.py", "print('fixed')\n")
        approved = self.helper("continue", review_id, "--message-file", self.message())
        second = f"refs/ko-review/{review_id}/round-002"
        self.assertEqual(approved["approved"]["ref"], second)
        self.assertEqual(self.git_out("diff", "--stat", ref, second).split("\n")[0].split()[0], "app.py")
        self.assertEqual(approved["inspect"], [
            f"ko-review export {review_id}  # the transcript, one section per round",
            f"git show {second}  # the last round's transcript, then its tree",
            f"git diff {ref} {second}  # what changed during the review",
            f"ko-review diff {review_id}  # your tree against the approved one",
        ])
        self.assertIn("### Codex: APPROVED", self.git_out("show", second))
        self.write("created-later.txt", "new\n")
        (self.repo / "app.py").write_text("print('edited after approval')\n")
        processes = [self.spawn("diff", review_id, "--", "--stat") for _ in range(3)]  # overlapping invocations
        outputs = [process.communicate(timeout=60) for process in processes]
        for process, (stat, stderr) in zip(processes, outputs):
            self.assertEqual(process.returncode, 0, stderr)
            changed = sorted(line.split()[0] for line in stat.splitlines()[:-1])
            self.assertEqual(changed, ["app.py", "created-later.txt"])
        process = self.spawn("diff", review_id, "--round", "1", "--", "--name-status")
        names, _ = process.communicate(timeout=60)
        self.assertIn("A\tcreated-later.txt", names)
        self.assertNotIn("untracked.txt", names)
        self.git("gc", "--prune=now", "-q")
        self.assertEqual(self.git_out("cat-file", "-t", second).strip(), "tag")
        self.assertEqual(self.git_out("cat-file", "-t", second + "^{tree}").strip(), "tree")
        journal = self.journal_of(review_id)
        self.assertEqual(journal[0]["snapshot"]["ref"], ref)
        self.assertEqual(journal[2]["snapshot"]["ref"], second)
        forgotten = self.helper("delete", review_id)
        self.assertEqual(sorted(forgotten["removedRefs"]), [ref, second])
        self.assertEqual(self.git_out("for-each-ref", f"refs/ko-review/{review_id}/"), "")
        self.assertEqual(self.helper("list")["reviews"], [])
        self.assertEqual(self.helper("show", review_id, expect=1)["error"]["code"], "UNKNOWN_REVIEW")

    def test_a_read_only_git_directory_leaves_the_round_without_a_snapshot(self):
        git_dir = self.repo / ".git"
        for path in [git_dir, *git_dir.rglob("*")]:
            if path.is_dir():
                path.chmod(0o555)
        self.addCleanup(lambda: [path.chmod(0o755) for path in [git_dir, *git_dir.rglob("*")] if path.is_dir()])
        self.write("untracked.txt", "new\n")
        output = self.start(APPROVED)
        self.assertEqual(output["status"], "APPROVED")
        self.assertIsNone(output["snapshots"][0]["ref"])
        self.assertIn("error", output["snapshots"][0])
        self.assertEqual(len(output["inspect"]), 1)
        self.assertTrue(output["inspect"][0].startswith(f"ko-review export {output['reviewId']}"))
        self.assertEqual(self.helper("verify", output["reviewId"])["approvalFresh"], True)

    def test_a_failed_round_still_carries_its_transcript_on_the_ref(self):
        self.plan({"exit": 1, "stderr": "boom"})
        error = self.helper("start", "codex", "--message-file", self.message("## Task\n\nmy request\n"), expect=1)
        ref = f"refs/ko-review/{error['reviewId']}/round-001"
        shown = self.git_out("show", ref)
        self.assertIn("my request", shown)
        self.assertIn("### Error: CODEX_FAILED", shown)
        tag = self.helper("list")["reviews"][0]["snapshots"][0]["tag"]
        self.assertEqual(tag, self.git_out("rev-parse", ref).strip())

    def test_a_transcript_write_failure_is_reported_and_leaves_the_tree_on_the_ref(self):
        import shutil
        real_git = shutil.which("git")
        wrapper = self.bin / "git"
        wrapper.write_text("\n".join([
            "#!/usr/bin/env python3",
            "import os, subprocess, sys",
            "mode = os.environ.get('FAKE_GIT_FAIL')",
            "if mode == 'mktag' and sys.argv[1:2] == ['mktag']:",
            "    sys.stderr.write('mktag refused'); sys.exit(1)",
            "if mode == 'update-ref-tag' and sys.argv[1:2] == ['update-ref'] and subprocess.run(",
            f"        [{real_git!r}, 'cat-file', '-t', sys.argv[3]], capture_output=True, text=True",
            "        ).stdout.strip() == 'tag':",
            "    sys.stderr.write('ref refused'); sys.exit(1)",
            f"os.execv({real_git!r}, ['git', *sys.argv[1:]])",
        ]) + "\n")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        self.addCleanup(wrapper.unlink)
        for mode, diagnostic in (("mktag", "mktag refused"), ("update-ref-tag", "ref refused")):
            with self.subTest(mode):
                self.environment = {"FAKE_GIT_FAIL": mode}
                output = self.start(APPROVED)
                taken = output["snapshots"][0]
                self.assertEqual(output["status"], "APPROVED")
                self.assertIsNone(taken["tag"])
                self.assertIn(diagnostic, taken["transcriptError"])
                self.assertEqual(self.git_out("cat-file", "-t", taken["ref"]).strip(), "tree")
                self.assertNotIn("git show", " ".join(output["inspect"]))
                self.plan({"exit": 1, "stderr": "boom"})  # a failed turn reports both failures
                failed = self.helper("start", "codex", "--message-file", self.message(), expect=1)
                self.environment = {}
                self.assertEqual(failed["error"]["code"], "CODEX_FAILED")
                self.assertIn(diagnostic, failed["snapshots"][0]["transcriptError"])

    def test_a_snapshot_failure_in_diff_is_a_structured_error(self):
        review_id = self.start(APPROVED)["reviewId"]
        git_dir = self.repo / ".git"
        directories = [path for path in [git_dir, *git_dir.rglob("*")] if path.is_dir()]
        for path in directories:
            path.chmod(0o555)
        self.addCleanup(lambda: [path.chmod(0o755) for path in directories])
        self.write("app.py", "print('a blob git cannot write')\n")
        process = self.spawn("diff", review_id)
        stdout, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 1, stdout + stderr)
        self.assertNotIn("Traceback", stderr)
        output = json.loads(stdout)
        self.assertEqual((output["error"]["code"], output["reviewId"]), ("GIT_FAILED", review_id))
        self.assertIn("git add", output["error"]["message"])

    def test_an_unborn_repository_is_snapshotted(self):
        unborn = self.root / "unborn"
        unborn.mkdir()
        subprocess.run(["git", "init", "-q", str(unborn)], check=True)
        empty = self.helper("start", "codex", "--message-file", self.message(), cwd=unborn, expect=1)["error"]
        self.assertEqual(empty["code"], "NOTHING_TO_REVIEW")
        (unborn / "first.txt").write_text("first\n")
        subprocess.run(["git", "-C", str(unborn), "add", "first.txt"], check=True)  # staged, no commit yet
        (unborn / "first.txt").unlink()  # still in the index, gone from the tree
        gone = self.helper("start", "codex", "--message-file", self.message(), cwd=unborn, expect=1)["error"]
        self.assertEqual(gone["code"], "NOTHING_TO_REVIEW")
        (unborn / "first.txt").write_text("first\n")
        self.plan({"result": APPROVED})
        output = self.helper("start", "codex", "--message-file", self.message(), cwd=unborn)
        self.assertEqual(output["currentHead"], "unborn")
        ref = output["snapshots"][0]["ref"]
        listed = subprocess.run(
            ["git", "-C", str(unborn), "ls-tree", "--name-only", ref], capture_output=True, text=True,
        )
        self.assertEqual(listed.stdout.split(), ["first.txt"])

    def test_a_review_of_nothing_is_refused_before_it_exists(self):
        (self.repo / "work.py").unlink()
        error = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "NOTHING_TO_REVIEW")
        self.assertIn("--base REF", error["message"])
        self.assertEqual(self.helper("list")["reviews"], [])
        self.assertEqual(self.calls(), [])
        error = self.helper("start", "codex", "--base", "HEAD", "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "NOTHING_TO_REVIEW")
        self.write("app.py", "print('committed work')\n")
        self.git("commit", "-q", "-am", "work")
        self.plan({"result": APPROVED})
        started = self.helper("start", "codex", "--base", "main~1", "--message-file", self.message())
        self.assertEqual(started["round"], 1)
        self.write("app.py", "print('hi')\n")  # dirty against HEAD, but the edit restores the base's content
        error = self.helper("start", "codex", "--base", "main~1", "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "NOTHING_TO_REVIEW")
        self.assertNotIn("--base REF", error["message"])
        self.plan({"result": APPROVED})
        self.assertEqual(self.helper("start", "codex", "--message-file", self.message())["round"], 1)
        self.git("checkout", "--", "app.py")
        self.write("untracked.txt", "new\n")
        self.plan({"result": APPROVED})
        self.assertEqual(self.helper("start", "codex", "--message-file", self.message())["round"], 1)
        (self.repo / "untracked.txt").unlink()
        wrapper = self.bin / "git"
        import shutil
        real_git = shutil.which("git")
        wrapper.write_text("\n".join([
            "#!/usr/bin/env python3",
            "import os, sys",
            "if sys.argv[1:2] == ['diff']:",
            "    sys.stderr.write('fatal: diff refused'); sys.exit(128)",
            f"os.execv({real_git!r}, ['git', *sys.argv[1:]])",
        ]) + "\n")
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        self.addCleanup(wrapper.unlink)
        error = self.helper("start", "codex", "--message-file", self.message(), expect=1)["error"]
        self.assertEqual((error["code"], "diff refused" in error["stderr"]), ("GIT_FAILED", True))

    def test_base_names_the_range_codex_reviews(self):
        self.write("app.py", "print('committed work')\n")
        self.git("commit", "-q", "-am", "work")
        self.plan({"result": APPROVED})
        output = self.helper("start", "codex", "--base", "main~1", "--message-file", self.message())
        self.assertEqual(output["base"], {"ref": "main~1", "commit": self.git_out("rev-parse", "main~1").strip()})
        prompt = self.calls()[0]["prompt"]
        self.assertIn("# Scope", prompt)
        self.assertIn("`git diff " + output["base"]["commit"] + "`", prompt)
        self.assertNotIn("`git diff main~1`", prompt)
        self.assertLess(prompt.index("# Scope"), prompt.index("# Review request"))
        self.assertNotIn("git diff HEAD", prompt)
        unknown = self.helper("start", "codex", "--base", "nowhere", "--message-file", self.message(), expect=1)
        self.assertEqual(unknown["error"]["code"], "BASE_UNKNOWN")
        self.start()
        self.assertIn("`git diff HEAD` plus untracked files", self.calls()[-1]["prompt"])

    def test_a_stale_approval_says_why(self):
        self.write("untracked.txt", "new\n")
        review_id = self.start(APPROVED)["reviewId"]
        self.assertEqual(self.helper("show", review_id)["staleReasons"], [])
        self.write("app.py", "print('edited')\n")
        (self.repo / "untracked.txt").unlink()
        self.write("added.txt", "added\n")
        stale = self.helper("verify", review_id, expect=1)["error"]
        self.assertEqual(stale["staleReasons"],
                         [{"reason": "working files changed", "paths": ["added.txt", "app.py", "untracked.txt"]}])
        self.write("app.py", "print('hi')\n")
        (self.repo / "added.txt").unlink()
        self.write("untracked.txt", "new\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "approved content")  # a changed HEAD alone is no reason
        self.assertEqual(self.helper("show", review_id)["staleReasons"], [])
        self.write("app.py", "print('staged only')\n")
        self.git("add", "app.py")
        self.write("app.py", "print('hi')\n")
        stale = self.helper("verify", review_id, expect=1)["error"]
        self.assertEqual(stale["staleReasons"], [{"reason": "unreviewed content staged", "paths": ["app.py"]}])
        self.git("reset", "-q", "app.py")
        self.plan({"exit": 1, "stderr": "boom"})
        self.helper("continue", review_id, "--instructions-file", self.message("Be strict.\n"),
                    "--message-file", self.message(), expect=1)
        stale = self.helper("verify", review_id, expect=1)["error"]
        self.assertEqual(stale["staleReasons"],
                         [{"reason": "the review instructions changed after the approval", "paths": []}])
        self.plan({"result": APPROVED})
        self.helper("continue", review_id, "--message-file", self.message())
        self.assertEqual(self.helper("show", review_id)["staleReasons"], [])

    def test_new_instructions_void_the_approval_until_codex_approves_again(self):
        review_id = self.start(APPROVED)["reviewId"]
        self.helper("verify", review_id)
        self.plan({"exit": 1, "stderr": "boom"})
        stricter = self.message("Be strict.\n")
        error = self.helper("continue", review_id, "--instructions-file", stricter,
                            "--message-file", self.message(), expect=1)
        self.assertEqual(error["error"]["code"], "CODEX_FAILED")
        self.assertEqual((error["reviewId"], error["status"]), (review_id, "APPROVED"))
        self.assertEqual(self.helper("verify", review_id, expect=1)["error"]["effectiveStatus"], "STALE_APPROVAL")

    def test_failures_name_the_review_and_its_inspect_lines(self):
        self.plan({"exit": 1, "stderr": "boom"})
        error = self.helper("start", "codex", "--message-file", self.message(), expect=1)
        review_id = self.helper("list")["reviews"][0]["reviewId"]
        self.assertEqual(error["reviewId"], review_id)
        self.assertEqual(error["status"], "NEW")
        self.assertTrue(error["inspect"][0].startswith(f"ko-review export {review_id}"))
        self.assertNotIn("reviewId", self.helper("show", "no-such-review", expect=1))

    def test_export_renders_the_transcript(self):
        instructions = self.message("Be strict.\n")
        self.plan({"result": CHANGES}, {"result": USER_DECIDES})
        review_id = self.helper("start", "codex", "--instructions-file", instructions,
                                "--message-file", self.message("## Task\n\nthe task\n"))["reviewId"]
        self.helper("continue", review_id, "--instructions-file", self.message("Be lenient.\n"),
                    "--message-file", self.message("## Rebutted findings\n\nF1 is fine\n"))
        self.assertIn("Be lenient.", self.calls()[1]["prompt"])
        self.helper("escalate", review_id, "--message-file", self.message("agreed\n"))
        process = self.spawn("export", review_id)
        markdown, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertLess(markdown.index("## Round 1"), markdown.index("Be strict."))
        self.assertLess(markdown.index("Be strict."), markdown.index("### Task"))
        self.assertLess(markdown.index("## Round 2"), markdown.index("Be lenient."))
        for text in (f"# Codex review {review_id}", "- Status: USER_DECISION_REQUIRED",
                     "### Instructions from the user, from this round on",
                     "Be lenient.", "## Round 1", f"Snapshot: `refs/ko-review/{review_id}/round-001`", "### The author",
                     "### Task", "### Codex: CHANGES_REQUESTED", "- **F1** (high) `app.py:1`: d", "Evidence: e",
                     "## Round 2", "### Codex: USER_DECISION_REQUIRED", "- Decision requested: d",
                     "### The author agreed that the user must decide", "## How to see how it went",
                     f"ko-review export {review_id}"):
            self.assertIn(text, markdown)

    def test_start_names_the_reviewer_and_continue_reads_it_from_the_review(self):
        review_id = self.start()["reviewId"]
        self.assertEqual(self.helper("show", review_id)["reviewer"], "codex")
        state_path = Path(self.helper("show", review_id)["statePath"])
        state = json.loads(state_path.read_text())
        state["reviewer"] = "agy"
        state_path.write_text(json.dumps(state))
        error = self.helper("continue", review_id, "--message-file", self.message(), expect=1)["error"]
        self.assertEqual(error["code"], "REVIEWER_UNSUPPORTED")
        without = ("start", "--message-file", self.message())
        unknown = ("start", "agy", "--message-file", self.message())
        for arguments in (without, unknown):
            process = self.spawn(*arguments)
            _, stderr = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 2, stderr)  # no reviewer, or an unknown one: a usage error

    def test_plugin_manifest_and_skill_agree_on_names(self):
        manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text())
        self.assertEqual(manifest["name"], "ko-review")
        skill = (PLUGIN / "skills/codex/SKILL.md").read_text()
        self.assertIn("ko-review start codex --message-file", skill)
        for command in ("continue", "escalate", "verify"):
            self.assertIn(f"ko-review {command} REVIEW_ID", skill)
        self.assertTrue(os.access(HELPER, os.X_OK))


if __name__ == "__main__":
    unittest.main()
