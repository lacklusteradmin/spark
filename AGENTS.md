## Git

Never run `git commit`, `git stage`, `git reset`, or any other git state-modifying command without the user explicitly asking. After finishing code edits, stop. The user will say "commit this" when they want a commit. The check to run before a commit is under "CHANGELOG" below.

## Project status

Spark is prelaunch — no existing users. When changing storage formats, DB schemas, keychain keys, or serialized structures, change them directly. Skip migration shims and backward-compat code entirely.

## Docs

Documentation lives in `docs/` under uppercase file names (`docs/SPARK-SPEC.md`, `docs/PROTOCOL.md`, `docs/CHANGELOG.md`). Chinese documents live in `docs/zh/`; a Chinese copy keeps the English file's name (`docs/zh/SPARK-SPEC.md`), and a Chinese-only document gets an uppercase name of its own (`docs/zh/CLI.md`). Only `README.md`, `AGENTS.md` and `CLAUDE.md` stay at the repository root. Refer to a document by its repository path, code comments included (`` `docs/SPARK-SPEC.md` F7 ``). The `.toml` registers in `docs/` are read by the invariant tests and keep their lowercase names. (The user moved the root `Spark-*.md` files into `docs/`, uppercased the names and put the Chinese copies in `docs/zh/` on 2026-11-24; new documents follow the same rule.)

## CHANGELOG

`docs/CHANGELOG.md` records what changed and why, newest first, one section per commit. Every change goes under `## Uncommitted` as it is made.

**Tidying:** before the user commits (for example when asked to tidy the CHANGELOG), check `## Uncommitted` against the actual change (`git diff`). Every sub-entry must match one change in the diff; delete the ones that don't (usually unchanged parts, the full after-picture, or process). Add what the diff has and the entries don't. Numbers must match the code, and the wording must not claim more than was done. Then rename the heading to the commit's title (`## Beta Commit 11`).

**How to write:**

- **Tone:** an objective record. Don't address the reader ("you"), no chatty asides. Decisions the user has to make go in the conversation, not here.
- **Only the changed result:** write what the changed thing is like now; where needed, one sentence in brackets for what it was before or why. No process ("first … then", "found … so", "tried …", the debugging story). No full after-picture either: that lives in the README, `docs/SPARK-SPEC.md`, `docs/SPARK-BUILD-NOTES.md` or `docs/PROTOCOL.md`, and the entry points there in a phrase.
- **One change, one sub-entry:** one bold short title per change, stating the result, with where it lives in brackets (file, type, function). Under it, one sub-entry per change, one or two sentences each. "One change" is something that can be matched in `git diff`: a behavior, a number or default, an interface or file that moved, whether old data still works. Many changes, many sub-entries; a change with a single point is the title line alone.
- **No padding:** these aren't changes and don't get written: parts that didn't change (unless a reader would assume they did); per-item appearance and algorithm details (they belong in the docs or code comments); lists of functions and call sites; mechanical edits such as added fields or renames; a restatement of the title. A refactor that keeps behavior gets one line saying what was merged into what; how that was shown goes under `Measured`.
- **Measurements:** the conclusion only, with its source (a file under `docs/`, a test).
- **Each section ends with, in this order** (leave out what doesn't apply):
  - `Measured`: one line per run, "date, conditions, result", key numbers only, before → after.
  - `Tests added: N`: one line per area, "area N: what it guards against". Don't list what each test checks. Existing tests that were adjusted along the way aren't mentioned unless what they guard changed.
  - `Docs`: which documents and which sections.
  - `Total` (every section has it, last): N .rs files changed (M new), +X / −Y lines; data and config files (by name, or "none"); dependencies unchanged, or what was added or removed; tests from A to B (the pass count of `cargo test --workspace`). "No code changed" when none was.
