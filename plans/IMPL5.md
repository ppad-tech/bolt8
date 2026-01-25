# IMPL5: Eliminate non-exhaustive test pattern matches

## Goal
Remove non-exhaustive pattern match warnings when running tests.

## Steps
1) Identify the warning locations by grepping for partial pattern
   matches in tests (e.g., `let Just`, `Right`, or direct field access).
2) Replace brittle matches with total helpers:
   - Use small helper functions like `expectRight`/`expectJust`
     that fail the test with an assertion message.
   - Avoid `error` and unchecked indexing.
3) For repeated handshake setup, add a helper returning either
   `Assertion` failure or the needed values, keeping each test
   total and readable.
4) Ensure all tests handle the full set of constructors explicitly
   (`Left`/`Right`, `Nothing`/`Just`, `FrameResult` variants).
5) Re-run `cabal test` to confirm warnings are gone.

## Notes
- Keep helpers local to `test/Main.hs`.
- Preserve existing test coverage and intent.
