# ARCH1: Packet framing for decrypt

## Goal
Define how the API should handle stream framing and trailing bytes when
receiving BOLT8 packets.

## Context
BOLT8 frames are sent on a stream as:
- encrypted length (2 bytes) + MAC (16 bytes) == 18 bytes total
- encrypted body (len bytes) + MAC (16 bytes)

A receiver typically reads 18 bytes, decrypts length, then reads the
next len+16 bytes. If a read returns more than one frame, the caller
must retain the remainder for the next decrypt.

## Decision points
- Keep strict packet API (reject trailing bytes), or
- Provide a framing helper that returns (plaintext, remainder, session),
  leaving existing decrypt unchanged.

## Constraints
- Preserve BOLT8 wire semantics.
- Avoid partial functions.
- Keep changes minimal and compatible where possible.

## Expected outcome
A clear API contract for decrypt framing in downstream callers, with
explicit behavior on trailing bytes.
