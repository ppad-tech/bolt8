# IMPL6: Add property-based tests

## Goal
Add a small set of QuickCheck properties to complement spec vectors and
negative tests.

## Constraints
- Use tasty-quickcheck only in the test suite.
- Keep generators small and deterministic enough for CI.
- No new dependencies beyond QuickCheck (already permitted for tests).

## Properties
1) Handshake round-trip:
   - For random static keys and fixed entropy for ephemeral keys,
     a full handshake succeeds and the derived sessions are consistent:
     initiator send key == responder recv key, and vice versa.
2) Encrypt/decrypt round-trip:
   - For random payloads of size 0..256 bytes, encrypt then decrypt
     yields the original payload and advances sessions.
3) Framing:
   - For random payloads, decrypt_frame consumes exactly one frame and
     returns the remainder when concatenated with a second frame.
   - decrypt_frame_partial returns NeedMore when given a prefix shorter
     than 18 bytes, and FrameOk when given a full frame.

## Implementation notes
- Add small helpers to generate valid Sec/Pub pairs from 32-byte
  entropy (filter invalid scalars).
- Use fixed ephemeral entropy in properties for determinism, or
  generate both static and ephemeral keys while rejecting invalid input.
- Add QuickCheck size limits to keep runtime fast.

## Steps
1) Add tasty-quickcheck dependency to test-suite if not already present.
2) Implement generators for 32-byte entropy and payload ByteStrings.
3) Add property tests to `test/Main.hs` under a new test group.
4) Run `cabal test` to confirm runtime and determinism.
