# ARCH2: Document HKDF invariant

## Goal
Document why mix_key cannot hit the Nothing case from HKDF.derive.

## Context
mix_key uses HKDF.derive hmac ck mempty 64 ikm and currently calls
error on Nothing. The Nothing case occurs when the requested output
length exceeds 255 * hashlen. For SHA256, hashlen is 32, so the limit
is 8160 bytes. The requested length is 64.

## Decision
Keep the error, but document the invariant in a short comment so future
readers understand why the case is impossible.

## Expected outcome
A local comment near mix_key explaining the bound and why error is safe
in this context.
