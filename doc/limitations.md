# Limitations

## Permission prompts that remain

### `claude`

A prompt remains for an `rm` or `rmdir` that Claude Code resolves to a
[critical path](https://code.claude.com/docs/en/permission-modes#critical-paths), such as
`rm -rf *` in the project directory (observed with Claude Code 2.1.276). No permission mode or
allow rule in the managed settings removes it.

1. Claude Code resolves a relative target against its working directory when it cannot follow a
   `cd`, as in `cd $_ && rm -rf *`, so the prompt can name a project path the command would not
   remove.
1. Read the whole command before approving: the `rm` can sit deep in a long script.
1. To make the prompt rarer and the prompted command short, the image's
   [AGENTS-SANDBOX.md](../container/ko-agent-sandbox/AGENTS-SANDBOX.md) tells agents how to write
   an `rm -rf`.
