# Repository instructions

This repository is a Codex skill for a real home gateway and firewall. Reliability, inspectability, and reversibility outrank convenience.

- Track `dlewis7444/unifi-claude-skill` as `upstream`; preserve `scripts/udm.py` closely so upstream diffs stay useful. Add HomeLab logic elsewhere.
- Default to read-only. Never live-test mutations without an exact user request and explicit authorization. Audit recommendations are not authorization.
- Never print or commit API keys, passwords, tokens, `.env`, raw inventory, reports, or snapshots. Redact recursively, including errors and debug logs.
- Maintain the four permission levels and the discover/snapshot/diff/approve/apply/verify/report sequence documented in `references/mutation-safety.md`.
- Use full-object GET/deep-copy/PUT semantics when an API requires replacement. Never synthesize missing fields.
- Treat protected resources and unknown objects as Level 3. Never claim control of the HP ProCurve.
- All automated tests must mock transport and must not contact a controller. Run `python -m unittest discover -s tests -v` before commits.
- Keep commits focused; do not force-push, rewrite upstream history, or mix secrets/generated artifacts into source commits.
- Update documentation and tests with behavior. Clearly mark official Integration API versus private/legacy, version-sensitive API behavior.
