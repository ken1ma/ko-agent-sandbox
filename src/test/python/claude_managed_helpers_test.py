import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[3]
SCRIPTS = PROJECT / "container/ko-agent-sandbox/claude-code"
FORMATTING = runpy.run_path(str(SCRIPTS / "command/statusLine.py"))


class ManagedHelpersTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="claude-managed-helpers-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def write(self, relative, content):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path

    def run_script(self, name, data, environment=None, args=(), raw=False):
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPTS / name), *args],
            input=data if raw else json.dumps(data),
            cwd=self.project,
            env={
                **{name: value for name, value in os.environ.items() if not name.startswith("KO_CLAUDE_")},
                **(environment or {}),
            },
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_template_paths_types_missing_and_single_pass(self):
        data = {
            "model": {"display_name": "${effort.level}", "id": "opus"},
            "effort": {"level": "high"},
            "count": 12,
            "fraction": 1.5,
            "enabled": False,
            "absent": None,
            "list": [1],
        }
        output = FORMATTING["render"](
            "${model.display_name}|${model.id}|${count}|${fraction}|${enabled}|"
            "${missing}|${absent}|${list}|${model}|${count.value}", data,
        )
        self.assertEqual(output, "${effort.level}|opus|12|1.5|false|||||")
        self.assertEqual(FORMATTING["render"]("${model.id} ${effort.level}", {"model": {"id": "opus"}}), "opus")

    def test_dollar_escaping_and_substitution_use_one_pass(self):
        data = {"cost": {"total_cost_usd": 1.25}, "literal": "$${cost.total_cost_usd}"}
        cases = {
            "$$": "$",
            "cost=$${cost.total_cost_usd}": "cost=${cost.total_cost_usd}",
            "cost=$$${cost.total_cost_usd}": "cost=$1.25",
            "$$$${cost.total_cost_usd}": "$${cost.total_cost_usd}",
            "$$$$${cost.total_cost_usd}": "$$1.25",
            "$${missing}|$$${missing}": "${missing}|$",
            "${literal}": "$${cost.total_cost_usd}",
            "$$ trailing $": "$ trailing $",
        }
        for template, expected in cases.items():
            with self.subTest(template=template):
                self.assertEqual(FORMATTING["render"](template, data), expected)

    def test_fallback_applies_only_to_missing_or_null_fields(self):
        template = "context ${context_window.used_percentage.getOrElse(0)}%"
        for data in ({}, {"context_window": None}, {"context_window": {}},
                     {"context_window": {"used_percentage": None}}):
            with self.subTest(data=data):
                self.assertEqual(FORMATTING["render"](template, data), "context 0%")
        for value, expected in [(0, "0"), (4, "4"), (False, "false"), ("", ""), ([], ""), ({}, "")]:
            with self.subTest(value=value):
                self.assertEqual(FORMATTING["render"]("${value.getOrElse(9)}", {"value": value}), expected)
        self.assertEqual(
            FORMATTING["render"]("${model.getOrElse}", {"model": {"getOrElse": "field value"}}),
            "field value",
        )

    def test_fallback_literals_escaping_and_invalid_expressions(self):
        cases = {
            '${missing.getOrElse("unknown")}': "unknown",
            '${missing.getOrElse("")}': "",
            '${missing.getOrElse(true)}': "true",
            '${missing.getOrElse(false)}': "false",
            '${missing.getOrElse( -1.25e2 )}': "-125.0",
            '${missing.getOrElse("${model.id} $$")}': "${model.id} $$",
            '$${missing.getOrElse(0)}': '${missing.getOrElse(0)}',
            '$$${missing.getOrElse(0)}': '$0',
            r'${missing.getOrElse("a\n\u001b\"b")}': 'a"b',
        }
        for template, expected in cases.items():
            with self.subTest(template=template):
                self.assertEqual(FORMATTING["render"](template, {}), expected)
        for literal in ["1 + 2", "SECRET", "[]", "{}", "null", "NaN", "1e999", "01", "'text'",
                        "__import__('os').system('touch executed')"]:
            template = "${missing.getOrElse(" + literal + ")}"
            with self.subTest(literal=literal):
                result = self.run_script("command/statusLine.py", {}, {"KO_CLAUDE_STATUSLINE_FORMAT": template})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.rstrip("\n"), template)
                self.assertFalse((self.project / "executed").exists())

    def test_project_format_handles_initial_and_reported_context_usage(self):
        settings = json.loads((PROJECT / ".claude/settings.json").read_text())
        data = {"model": {"display_name": "Fable 5.1"}, "effort": {"level": "high"}}
        for value, expected in [(None, "0"), (0, "0"), (4, "4")]:
            with self.subTest(value=value):
                data["context_window"] = {"used_percentage": value}
                result = self.run_script("command/statusLine.py", data, settings["env"])
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, f"Fable 5.1 high, context {expected}%\n")

    def test_template_cannot_execute_or_access_environment(self):
        marker = self.project / "executed"
        self.write("sitecustomize.py", "raise RuntimeError('project startup code ran')")
        self.write("json.py", "raise RuntimeError('project import ran')")
        template = "$(touch executed) ${SECRET} ${__import__('os').system('touch executed')} ${model.id}"
        result = self.run_script(
            "command/statusLine.py", {"model": {"id": "opus"}},
            {"KO_CLAUDE_STATUSLINE_FORMAT": template, "SECRET": "hidden", "PYTHONPATH": str(self.project)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("$(touch executed)", result.stdout)
        self.assertNotIn("hidden", result.stdout)
        self.assertFalse(marker.exists())

    def test_template_disabled_invalid_bounded_and_terminal_output(self):
        result = self.run_script("command/statusLine.py", "not JSON", raw=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        result = self.run_script("command/statusLine.py", [], {"KO_CLAUDE_STATUSLINE_FORMAT": "${model.id}"})
        self.assertNotEqual(result.returncode, 0)
        with self.assertRaisesRegex(ValueError, "4096"):
            FORMATTING["render"]("x" * 4097, {})
        result = self.run_script("command/statusLine.py", " " * (2 * 1024 * 1024 + 1),
                                 {"KO_CLAUDE_STATUSLINE_FORMAT": "x"}, raw=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(FORMATTING["render"]("${value}", {"value": "a\n\x1b\x07\u202eb"}), "ab")
        self.assertEqual(len(FORMATTING["render"]("${value}" * 100, {"value": "a" * 10000})), 4096)
        fallback = "${value.getOrElse(" + json.dumps("x" * 4000) + ")}"
        with self.assertRaisesRegex(ValueError, "4096"):
            FORMATTING["render"](fallback + "x" * 100, {})
        self.assertEqual(len(FORMATTING["render"](fallback + "${large}", {"large": "y" * 4096})), 4096)

    def test_hyperlink_controls_are_removed_from_templates_and_values(self):
        sequences = [
            "\x1b]8;;https://example.com\x07label\x1b]8;;\x07",
            "\x1b]8;;https://example.com\x1b\\label\x1b]8;;\x1b\\",
            "\x9d8;;https://example.com\x9clabel\x9d8;;\x9c",
        ]
        for sequence in sequences:
            cases = [
                (sequence, {}),
                ("${model.display_name}", {"model": {"display_name": sequence}}),
                ("${missing.getOrElse(" + json.dumps(sequence) + ")}", {}),
            ]
            for template, data in cases:
                with self.subTest(sequence=sequence, template=template):
                    result = self.run_script(
                        "command/statusLine.py", data, {"KO_CLAUDE_STATUSLINE_FORMAT": template},
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("label", result.stdout)
                    self.assertTrue(all(character.isprintable() for character in result.stdout.removesuffix("\n")))

    def test_registration_contains_only_status_line(self):
        settings_directory = SCRIPTS / "managed-settings.d"
        self.assertEqual({path.name for path in settings_directory.glob("*.json")}, {"statusLine.json"})
        settings = json.loads((settings_directory / "statusLine.json").read_text())
        self.assertEqual(settings, {
            "statusLine": {
                "type": "command",
                "command": "/usr/local/bin/python3 -I /etc/claude-code/command/statusLine.py",
            },
        })
        self.assertEqual(
            {path.relative_to(SCRIPTS).as_posix() for path in SCRIPTS.rglob("*.py")},
            {"command/statusLine.py"},
        )


if __name__ == "__main__":
    unittest.main()
