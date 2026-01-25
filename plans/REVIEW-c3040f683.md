# Review c3040f683

## Findings
- Low: Doc mismatch between encrypt and decrypt about key-rotation cadence.
  encrypt says "every 500 messages" while decrypt/decrypt_frame say 1000.
  This is misleading for callers reading Haddocks. See
  lib/Lightning/Protocol/BOLT8.hs:503.

## Notes
- If you want a recoverable/partial state ("need more bytes") rather than
  InvalidLength, that needs an API/ADT change; see ARCH/IMPL proposal.
