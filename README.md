# ppad-bolt8

[![](https://img.shields.io/hackage/v/ppad-bolt8?color=blue)](https://hackage.haskell.org/package/ppad-bolt8)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-bolt8-lightblue)](https://docs.ppad.tech/bolt8)

A pure Haskell implementation of [BOLT #8][bolt8], the Lightning
Network's encrypted and authenticated transport: the
`Noise_XK_secp256k1_ChaChaPoly_SHA256` handshake, followed by
length-prefixed, authenticated encryption of messages with periodic key
rotation.

## Usage

A sample GHCi session:

```
  > :set -XOverloadedStrings
  > import qualified Data.ByteString as BS
  > import qualified Lightning.Protocol.BOLT8 as BOLT8
  >
  > -- static keypairs (use 32 bytes of secure randomness in practice)
  > let Just i = BOLT8.keypair (BS.replicate 32 0x11)
  > let Just r = BOLT8.keypair (BS.replicate 32 0x21)
  >
  > -- ephemeral entropy MUST be fresh, uniformly random bytes
  > let i_ent = BS.replicate 32 0x12
  > let r_ent = BS.replicate 32 0x22
  >
  > -- the initiator knows the responder's static public key
  > let Right (msg1, i_hs) = BOLT8.act1 i (BOLT8.keypair_pub r) i_ent
  > let Right (msg2, r_hs) = BOLT8.act2 r r_ent msg1
  > let Right (msg3, i_res) = BOLT8.act3 i_hs msg2
  > let Right r_res = BOLT8.finalize r_hs msg3
  >
  > -- the responder has authenticated the initiator's static key
  > BOLT8.handshake_remote_static r_res == BOLT8.keypair_pub i
  True
  >
  > -- each side gets a Sender and a Receiver
  > let i_snd = BOLT8.handshake_sender i_res
  > let r_rcv = BOLT8.handshake_receiver r_res
  >
  > -- every operation returns the next state; never reuse an old one
  > let Right (ct, i_snd') = BOLT8.encrypt i_snd "hello"
  > let Right (pt, r_rcv') = BOLT8.decrypt r_rcv ct
  > pt
  "hello"
  >
  > -- on a byte stream: decrypt the 18-byte header, which says how many
  > -- bytes to read next, then decrypt the rest of the frame
  > let Right (ct', _) = BOLT8.encrypt i_snd' "world"
  > let (hdr, rest) = BS.splitAt 18 ct'
  > let Right (n, pending) = BOLT8.decrypt_header r_rcv' hdr
  > n
  21
  > fmap fst (BOLT8.decrypt_body pending (BS.take n rest))
  Right "world"
```

The `Sender` and `Receiver` are independent, so a writer thread can own
one and a reader thread the other. Any error from a handshake or
transport function means the connection must be closed.

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/bolt8][hadoc].

## Specification

This library implements BOLT #8 as of [lightning/bolts@1aadb719][spec]
(2026-09-21), a copy of which is in `etc/08-transport.md`.

The library is pure, and leaves the following to the caller:

* Network I/O, including reading exactly the number of bytes each step
  requires, and terminating the connection on any failure.
* Generating ephemeral keys: `act1` and `act2` take the ephemeral
  secret key as 32 bytes of caller-supplied entropy.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The implementation passes all BOLT #8 Appendix A test vectors,
including every handshake failure case and the message vectors spanning
two key rotations. The cryptography is provided by
[ppad-secp256k1][secp] (ECDH, using constant-time scalar
multiplication), [ppad-aead][aead] (ChaCha20-Poly1305, with
constant-time MAC verification), [ppad-hkdf][hkdf] and
[ppad-sha256][sha256].

Session state is a pure value that each operation advances. Reusing an
old `Sender` reuses a nonce, and reusing an old `Receiver` accepts
replayed frames; see the module documentation.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

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

[bolt8]: https://github.com/lightning/bolts/blob/master/08-transport.md
[spec]: https://github.com/lightning/bolts/blob/1aadb719b4007c4cea0ba6e36b08c4fb53788dee/08-transport.md
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/bolt8
[const]: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
[secp]: https://git.ppad.tech/secp256k1
[aead]: https://git.ppad.tech/aead
[hkdf]: https://git.ppad.tech/hkdf
[sha256]: https://git.ppad.tech/sha256
