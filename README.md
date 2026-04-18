# ppad-bolt8

[![](https://img.shields.io/hackage/v/ppad-bolt8?color=blue)](https://hackage.haskell.org/package/ppad-bolt8)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-bolt8-lightblue)](https://docs.ppad.tech/bolt8)

Haskell implementation of BOLT #8 (Lightning Network encrypted
transport), including the `Noise_XK_secp256k1_ChaChaPoly_SHA256` handshake
and encrypted message transport.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  >
  > import qualified Data.ByteString as BS
  > import qualified Lightning.Protocol.BOLT8 as BOLT8
  >
  > let Just (i_s_sec, i_s_pub) = BOLT8.keypair (BS.replicate 32 0x11)
  > let Just (r_s_sec, r_s_pub) = BOLT8.keypair (BS.replicate 32 0x21)
  >
  > -- initiator knows responder static pubkey
  > let Right (msg1, i_hs) = BOLT8.act1 i_s_sec i_s_pub r_s_pub
  >                         (BS.replicate 32 0x12)
  > let Right (msg2, r_hs) = BOLT8.act2 r_s_sec r_s_pub
  >                         (BS.replicate 32 0x22) msg1
  > let Right (msg3, i_res) = BOLT8.act3 i_hs msg2
  > let Right r_res = BOLT8.finalize r_hs msg3
  >
  > let i_sess = BOLT8.session i_res
  > let r_sess = BOLT8.session r_res
  >
  > let Right (ct, i_sess') = BOLT8.encrypt i_sess "hello"
  > let Right (pt, r_sess') = BOLT8.decrypt r_sess ct
  > pt
  "hello"
```

## Framing

On a byte stream, use `decrypt_frame` when you have an exact frame, or
`decrypt_frame_partial` to work incrementally and learn how many bytes
are still required for the next step.

## Documentation

Haddocks are hosted at [docs.ppad.tech/bolt8][hadoc].

## Security

This is a pre-release library that, at present, claims no security
properties whatsoever.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal build
$ cabal test
$ cabal bench
```

[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/bolt8
