import json
import math
import os
import re
import sys


MAX_INPUT = 2 * 1024 * 1024
MAX_TEMPLATE = 4096
TEMPLATE_TOKEN = re.compile(r"\$\$|\$\{([A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*)\}")


def read_input():
    content = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(content) > MAX_INPUT:
        raise ValueError("status-line input exceeds 2 MiB")
    data = json.loads(content)
    if not isinstance(data, dict):
        raise ValueError("status-line input must be a JSON object")
    return data


def plain_text(value):
    return "".join(character for character in str(value) if character.isprintable())


def render(template, data):
    if len(template) > MAX_TEMPLATE:
        raise ValueError("format exceeds 4096 characters; shorten the format setting")

    def replace(match):
        if match.group(0) == "$$":
            return "$"
        value = data
        for name in match.group(1).split("."):
            if not isinstance(value, dict):
                return ""
            value = value.get(name)
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (str, int)):
            return plain_text(value)[:MAX_TEMPLATE]
        if isinstance(value, float) and math.isfinite(value):
            return str(value)
        return ""

    return plain_text(TEMPLATE_TOKEN.sub(replace, template)).strip()[:MAX_TEMPLATE]


def main():
    if sys.argv[1:]:
        raise ValueError("the status-line formatter takes no arguments")
    template = os.environ.get("KO_CLAUDE_STATUSLINE_FORMAT", "")
    if template:
        print(render(template, read_input()))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RecursionError) as ex:
        print(f"Claude status line: {ex}", file=sys.stderr)
        sys.exit(1)
