# Consistency layer

No AI. Compares new code with the rest of the repo, then Layer 3 judges the
findings like any other.

## Checks

1. **Missing guard** (high). For a new decorated function, its siblings are
   functions anywhere in the repo sharing a decorator (e.g. `@route`). If at
   least 3 siblings exist and at least 75% of them call a guard-like function
   (`check_owner`, `require_login`, ...) or raise an access error
   (`PermissionError`, `Forbidden`, ...) that the new one doesn't, it's flagged:
   "4 of 4 similar @route handlers call check_owner() before acting;
   delete_note doesn't". Based on "Bugs as Deviant Behavior" (Engler et al.,
   2001): the majority is probably right.
2. **Duplicate** (low, no AI). A new function whose body has the same structure
   as an existing one, ignoring names, with at least 3 statements.

## Notes

- "Guard-like" means the name matches `GUARD_WORDS` (owner, auth, permission,
  forbid, login, access, admin, role, csrf, verify, validate, require, allow,
  check). Shared non-guard calls like `log_event()` are never flagged.
- Findings sit on the function's `def` line, so the gate's added-lines filter
  keeps only functions this commit adds.
- Layer 3 keeps this layer's fix (the exact missing call) instead of the
  model's: the 1.5B model tended to copy the prompt's example guard.
- Repo files come from `git ls-files`, capped at 2,000; outside git it falls
  back to the staged files' folders.
- Not covered: duplicates rewritten with different logic (would need an
  embedding model), and patterns with fewer than 3 siblings.
