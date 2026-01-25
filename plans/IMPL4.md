# IMPL4: Recoverable partial framing

## Steps
1) Define a result ADT, e.g.:
   data FrameResult = NeedMore !Int
                    | FrameOk !ByteString !ByteString !Session
                    | FrameError !Error
2) Add a new function (decrypt_frame_partial) that returns FrameResult.
   - If buffer < 18, return NeedMore (18 - len).
   - If length decrypt fails due to short buffer, return NeedMore.
   - If buffer < 18 + len + 16, return NeedMore (needed bytes).
   - MAC/parse failures return FrameError.
3) Keep decrypt_frame strict or re-implement it as a wrapper that
   converts NeedMore into InvalidLength.
4) Add tests:
   - Buffer smaller than 18 returns NeedMore.
   - Buffer with full length header but short body returns NeedMore.
   - Full frame returns FrameOk with remainder.
5) Update Haddocks to describe partial behavior.

## Notes
- Use a new ADT to avoid breaking existing Error semantics.
- No new dependencies.
