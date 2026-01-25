# ARCH3: Doc fixes and negative tests

## Goal
Correct key-rotation documentation and add negative tests for
validation paths.

## Context
- Docs say rotate every 500 messages; code rotates at 1000.
- Tests only cover positive BOLT8 vectors.

## Changes
- Update Haddock comments to match implementation or spec.
- Add tests for:
  - Invalid lengths (short/extra).
  - Invalid version byte.
  - Invalid MAC.

## Constraints
- Use tasty + tasty-hunit.
- Use spec-aligned values and local helpers.
- No new dependencies.

## Expected outcome
Docs reflect actual behavior, and failures are covered by tests.
