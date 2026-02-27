# Agent Workflow Rules (Repository Local)

These rules apply to all coding-agent work in this repository.

1. Push-after-change rule
- If any source file is modified, stage, commit, and push to `origin/main` before proposing a run/restart command.
- Do not suggest `./run.sh` (or any runtime restart) while there are uncommitted or unpushed changes.

2. Pre-run verification checklist
- Run `git status --short` and confirm a clean working tree.
- Run `git log --oneline origin/main..HEAD` and confirm there are no local commits pending push.

3. Runtime artifacts
- Never commit transient runtime files (for example `.gntl-webadmin.pid`).

4. User preference precedence
- This push-first workflow is mandatory unless the user explicitly overrides it in the current conversation.
