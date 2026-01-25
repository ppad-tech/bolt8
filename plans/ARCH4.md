# ARCH4: Recoverable partial framing

## Goal
Distinguish "need more bytes" from malformed packets when decrypting
from a stream buffer.

## Context
Current decrypt_frame returns InvalidLength when the buffer does not
contain a full frame. In streaming reads, this can be a normal condition
rather than an error. BOLT8 framing requires incremental parsing of a
length field and then the encrypted body.

## Decision points
- Introduce a new result type (e.g., FrameResult) that can be:
  - NeedMore Int (minimum bytes required),
  - FrameOk plaintext remainder session,
  - FrameError Error.
- Alternatively, add a new function decrypt_frame_partial with a
  dedicated error type while keeping decrypt_frame strict.

## Constraints
- Keep existing API behavior stable if possible.
- Avoid partial functions.
- Make the partial/need-more case explicit and non-exceptional.

## Expected outcome
A clear API for streaming callers to handle partial buffers without
conflating them with invalid frames.
