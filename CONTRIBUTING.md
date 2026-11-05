# Contributing

Thanks for helping make this better.

## Add a scanner rule
1. Open `code-security-auditor/scripts/scan.py` and add an `R(...)` entry to `RULES`: id, name, CWE, severity, confidence, file extensions, regex, message, fix. Use `unless=` to exclude known false positives.
2. Add a matching vulnerable line to `tests/demo_project.py` and the rule id to `MUST_FIND` in `tests/test_scan.py`.
3. Add a safe example to the clean-project test if the rule could plausibly misfire on correct code.
4. Run `python -m unittest discover -s tests -v`.

Keep rules precise. A noisy rule costs more trust than a missed pattern; use `confidence: low` for heuristics.

## Add a stack checklist or fix pattern
Edit `references/frameworks.md` or `references/patterns.md`. Keep fixes minimal and behavior-preserving, show before/after, and note caveats (migrations, breaking changes).

## Rules for contributions
- Never commit real secrets or real-looking keys. Build fakes at runtime (see `tests/demo_project.py`).
- Keep `SKILL.md` description under 1024 characters and the file under 500 lines.
- No network calls in scripts; they must run offline with the standard library only.

## Reporting a problem with the skill
Open an issue with the prompt, the stack, and what was missed or wrongly flagged (redact secrets).
