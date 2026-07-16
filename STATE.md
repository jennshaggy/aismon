# STATE.md

Last updated: 2026-07-10

## Current Status

The core tool is built and functional. All code is committed and pushed to the private repo at github.com/jennshaggy/sysmon-parser. 56 tests pass. The repo is private pending review before going public.

## What Exists

| Component | Status | Notes |
|---|---|---|
| parser.py | Complete | Parses XML, extracts 10 fields, filters by image/user/integrity level |
| detector.py | Complete | Loads YAML rules, matches events, returns tagged alerts |
| detections/ | Complete | 35 rules across 6 YAML files (AI-001 through AI-035) |
| samples/ | Complete | 6 XML files (3 benign, 3 AI-specific) |
| tests/ | Complete | 56 tests (21 parser, 35 detector), all passing |
| CLAUDE.md | Complete | Dev reference for Claude Code sessions |
| HANDOFF.md | Complete | Full project summary with decisions and next steps |
| .gitignore | Complete | Excludes __pycache__, .pyc, .pytest_cache |
| README.md | Not started | Needed before going public |

## Git State

- Repo: github.com/jennshaggy/sysmon-parser (private)
- Branch: main
- Last commit: "Add Sysmon Event ID 1 parser with AI/LLM threat detection"
- Uncommitted files: HANDOFF.md, STATE.md (stage and push when ready)
- Git email set to jennshaggy@users.noreply.github.com (GitHub privacy noreply)

## Next Steps (Priority Order)

1. Write README.md for the public GitHub page
2. Set repo to public (`gh repo edit jennshaggy/sysmon-parser --visibility public`)
3. Add multi-file input support (glob or directory scanning)
4. Add CSV output format
5. Add `--rules-dir` flag for custom detection rule directories
6. Add time-range filtering (`--after`, `--before`)
7. Support Windows Event Log XML namespace prefixes
8. Add summary/stats mode (counts by severity and category)
9. GitHub Actions CI for tests on push
10. PyPI packaging

## Key Decisions to Remember

- YAML rules (not hardcoded) so security teams can contribute without touching Python
- AND logic for multi-condition rules to reduce false positives
- Case-insensitive substring matching for image/commandline, exact match for user
- Single dependency (PyYAML) to keep the tool easy to deploy
- `--detect` annotates all events, `--detect-only` filters to flagged events only
- No em-dashes in commit messages or copy (user preference)
- No "its not x, its y" rhetoric or common AI/ML writing patterns in copy (user preference)
