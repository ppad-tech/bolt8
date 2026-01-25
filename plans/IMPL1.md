# IMPL1: Packet framing for decrypt

## Steps
1) Decide API shape:
   - Option A: Make decrypt strict and require exact packet length.
   - Option B: Add decrypt_frame returning remainder, keep decrypt strict
     or unchanged.
2) If Option A:
   - Add length check that the buffer equals 18 + len + 16.
   - Return InvalidLength on trailing bytes.
3) If Option B:
   - Implement decrypt_frame :: Session -> ByteString
     -> Either Error (ByteString, ByteString, Session).
   - decrypt_frame consumes one frame and returns the remainder.
   - Keep existing decrypt strict or make it a wrapper over
     decrypt_frame that rejects remainder.
4) Add tests for framing behavior:
   - Trailing bytes rejected for strict decrypt.
   - decrypt_frame returns the correct remainder.

## Notes
- Align docstrings with the chosen behavior.
- No new dependencies.
