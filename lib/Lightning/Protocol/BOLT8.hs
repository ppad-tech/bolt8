{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Module: Lightning.Protocol.BOLT8
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Encrypted and authenticated transport for the Lightning Network, per
-- [BOLT #8](https://github.com/lightning/bolts/blob/master/08-transport.md):
-- the @Noise_XK_secp256k1_ChaChaPoly_SHA256@ handshake, followed by
-- length-prefixed, authenticated encryption of messages.
--
-- The library is pure; reading from and writing to the network is up
-- to the caller.
--
-- = Handshake
--
-- The /initiator/ knows the responder's static public key in advance.
-- It sends act one ('act1'), receives act two, and replies with act
-- three ('act3'). The /responder/ receives act one, replies with act two
-- ('act2'), and receives act three ('finalize'), which authenticates
-- the initiator's static key. Both sides end up with a t'Handshake'.
--
-- >>> :set -XOverloadedStrings
-- >>> import qualified Data.ByteString as BS
-- >>> let Just i = keypair (BS.replicate 32 0x11)
-- >>> let Just r = keypair (BS.replicate 32 0x21)
-- >>> -- initiator, knowing r's public key; entropy must be random!
-- >>> let Right (msg1, i_hs) = act1 i (keypair_pub r) (BS.replicate 32 0x12)
-- >>> -- responder
-- >>> let Right (msg2, r_hs) = act2 r (BS.replicate 32 0x22) msg1
-- >>> -- initiator
-- >>> let Right (msg3, i_res) = act3 i_hs msg2
-- >>> -- responder
-- >>> let Right r_res = finalize r_hs msg3
-- >>> handshake_remote_static r_res == keypair_pub i
-- True
--
-- = Transport
--
-- A t'Handshake' carries a t'Sender' for outgoing messages and a
-- t'Receiver' for incoming ones. They are independent, so a writer
-- thread can own the t'Sender' and a reader thread the t'Receiver'.
--
-- >>> let Right (ct, i_snd) = encrypt (handshake_sender i_res) "hello"
-- >>> fmap fst (decrypt (handshake_receiver r_res) ct)
-- Right "hello"
--
-- On a byte stream, read exactly 18 bytes and pass them to
-- 'decrypt_header', which returns the number of bytes to read next;
-- then read exactly that many bytes and pass them to 'decrypt_body'.
-- 'decrypt' does both for a buffer holding exactly one frame.
--
-- Keys rotate every 1000 nonces, i.e. every 500 messages in each
-- direction; this is handled internally. Messages are at most 65535
-- bytes.
--
-- = Security
--
-- * __Use each state exactly once.__ Every function that takes an
--   t'Initiator', t'Responder', t'Sender', t'Receiver' or t'Pending'
--   returns the next state, and the caller must continue with that.
--   States are ordinary immutable values, so nothing stops an old one
--   from being used again, and doing so is catastrophic: encrypting
--   twice with the same t'Sender' reuses a nonce, which reveals the XOR
--   of the two plaintexts and allows forgeries, and decrypting with an
--   old t'Receiver' accepts replayed frames.
--
-- * __Ephemeral entropy must be fresh.__ The 32 bytes passed to 'act1'
--   and 'act2' are used directly as the ephemeral secret key. They
--   must come from a cryptographically secure random source, be
--   uniformly random, and never be reused.
--
-- * __Any error is fatal.__ BOLT #8 requires terminating the
--   connection on any handshake or transport failure. Don't retry with
--   the previous state. The one exception is 'encrypt' rejecting an
--   oversized message, which advances nothing.

module Lightning.Protocol.BOLT8 (
    -- * Keys
    Keypair
  , keypair
  , keypair_pub
  , Pub
  , parse_pub
  , serialize_pub

    -- * Handshake
  , Handshake
  , handshake_sender
  , handshake_receiver
  , handshake_remote_static

    -- ** Initiator
  , Initiator
  , act1
  , act3

    -- ** Responder
  , Responder
  , act2
  , finalize

    -- * Transport
  , Sender
  , encrypt
  , Receiver
  , decrypt
  , Pending
  , decrypt_header
  , decrypt_body

    -- * Errors
  , Error(..)
  ) where

import Control.DeepSeq (NFData(..))
import Control.Monad (guard, unless)
import qualified Crypto.AEAD.ChaCha20Poly1305 as AEAD
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.KDF.HMAC as HKDF
import Data.Bits (unsafeShiftR, (.&.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BU
import Data.Word (Word8, Word16, Word64)
import GHC.Generics (Generic)

-- keys -----------------------------------------------------------------------

-- A secret key: 32 bytes encoding a valid secp256k1 scalar.
newtype Sec = Sec BS.ByteString

-- | A secp256k1 public key.
--
--   'Show' renders the 33-byte compressed encoding in hex.
newtype Pub = Pub Secp256k1.Projective

instance Eq Pub where
  Pub a == Pub b =
    Secp256k1.serialize_point a == Secp256k1.serialize_point b

instance Show Pub where
  showsPrec d p = showParen (d > 10) $
    showString "Pub " . shows (hex (serialize_pub p))

instance NFData Pub where
  rnf (Pub p) = p `seq` ()

-- | A secp256k1 keypair: a secret key and its public key.
--
--   Has no 'Show' or 'Eq' instance, as it contains secret material.
data Keypair = Keypair !Sec !Pub

instance NFData Keypair where
  rnf (Keypair (Sec s) p) = s `seq` rnf p

-- | Construct a keypair from a 32-byte secret key.
--
--   The bytes are used directly as the secret key, so they must be
--   uniformly random and kept secret. Returns 'Nothing' if the input
--   is not 32 bytes, or is not a valid secp256k1 secret key (zero, or
--   not less than the curve order).
--
--   >>> import Data.Maybe (isJust)
--   >>> isJust (keypair (BS.replicate 32 0x11))
--   True
--   >>> isJust (keypair (BS.replicate 32 0x00))
--   False
keypair :: BS.ByteString -> Maybe Keypair
keypair sec = do
  guard (BS.length sec == 32)
  k <- Secp256k1.parse_int256 sec
  p <- Secp256k1.derive_pub k
  pure $! Keypair (Sec sec) (Pub p)

-- | The public key of a keypair.
--
--   >>> let Just r = keypair (BS.replicate 32 0x21)
--   >>> keypair_pub r
--   Pub "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
keypair_pub :: Keypair -> Pub
keypair_pub (Keypair _ p) = p

-- | Parse a 33-byte compressed public key.
--
--   >>> let Just r = keypair (BS.replicate 32 0x21)
--   >>> parse_pub (serialize_pub (keypair_pub r)) == Just (keypair_pub r)
--   True
--   >>> parse_pub (BS.replicate 33 0x04)
--   Nothing
parse_pub :: BS.ByteString -> Maybe Pub
parse_pub bs = do
  guard (BS.length bs == 33)
  p <- Secp256k1.parse_point bs
  pure (Pub p)

-- | Serialize a public key in 33-byte compressed form.
--
--   >>> let Just r = keypair (BS.replicate 32 0x21)
--   >>> BS.length (serialize_pub (keypair_pub r))
--   33
serialize_pub :: Pub -> BS.ByteString
serialize_pub (Pub p) = Secp256k1.serialize_point p

-- handshake state ------------------------------------------------------------

-- | The initiator's handshake state between acts one and three.
--
--   Produced by 'act1' and consumed by 'act3'. Contains secret
--   material; use it once.
data Initiator = Initiator
  {-# UNPACK #-} !BS.ByteString -- handshake hash
  {-# UNPACK #-} !BS.ByteString -- chaining key
  !Sec                          -- ephemeral secret
  !Keypair                      -- local static keypair
  !Pub                          -- remote static public key

instance NFData Initiator where
  rnf (Initiator h ck (Sec e) s rs) =
    h `seq` ck `seq` e `seq` rnf s `seq` rnf rs

-- | The responder's handshake state between acts two and three.
--
--   Produced by 'act2' and consumed by 'finalize'. Contains secret
--   material; use it once.
data Responder = Responder
  {-# UNPACK #-} !BS.ByteString -- handshake hash
  {-# UNPACK #-} !BS.ByteString -- chaining key
  {-# UNPACK #-} !BS.ByteString -- temp_k2
  !Sec                          -- ephemeral secret

instance NFData Responder where
  rnf (Responder h ck k (Sec e)) = h `seq` ck `seq` k `seq` e `seq` ()

-- | The result of a successful handshake: the initial transport
--   states and the remote party's authenticated static public key.
--
--   Take the t'Sender' and t'Receiver' out once, right after the
--   handshake, and don't keep the t'Handshake' around: it always yields
--   the /initial/ states, and encrypting with the initial t'Sender'
--   a second time reuses a nonce.
data Handshake = Handshake !Sender !Receiver !Pub

instance NFData Handshake where
  rnf (Handshake s r p) = rnf s `seq` rnf r `seq` rnf p

-- | The initial t'Sender', for encrypting outgoing messages.
--
--   Call this once per handshake. Every call returns the same initial
--   state, so encrypting with the result of a second call reuses a
--   nonce.
handshake_sender :: Handshake -> Sender
handshake_sender (Handshake s _ _) = s

-- | The initial t'Receiver', for decrypting incoming messages.
--
--   Call this once per handshake. Every call returns the same initial
--   state, so decrypting with the result of a second call accepts
--   replayed frames.
handshake_receiver :: Handshake -> Receiver
handshake_receiver (Handshake _ r _) = r

-- | The remote party's static public key, authenticated by the
--   handshake. For the initiator, this is the key passed to 'act1'.
handshake_remote_static :: Handshake -> Pub
handshake_remote_static (Handshake _ _ p) = p

-- transport state ------------------------------------------------------------

-- One direction's cipher state.
data Cipher = Cipher
  {-# UNPACK #-} !BS.ByteString -- key
  {-# UNPACK #-} !Word64        -- nonce, always < 1000
  {-# UNPACK #-} !BS.ByteString -- chaining key

instance NFData Cipher where
  rnf (Cipher k n ck) = k `seq` n `seq` ck `seq` ()

-- | State for encrypting outgoing messages.
--
--   Each 'encrypt' returns the next t'Sender'. Never use a t'Sender'
--   twice: doing so reuses a nonce.
newtype Sender = Sender Cipher

instance NFData Sender where
  rnf (Sender c) = rnf c

-- | State for decrypting incoming messages.
--
--   Each 'decrypt' or 'decrypt_header' consumes the t'Receiver'.
--   Never use a t'Receiver' twice: doing so accepts replayed frames.
newtype Receiver = Receiver Cipher

instance NFData Receiver where
  rnf (Receiver c) = rnf c

-- | A t'Receiver' that has decrypted a frame header and awaits the
--   frame body.
--
--   Produced by 'decrypt_header' and consumed by 'decrypt_body'. Use
--   it once.
data Pending = Pending {-# UNPACK #-} !Int !Cipher

instance NFData Pending where
  rnf (Pending n c) = n `seq` rnf c

-- errors ---------------------------------------------------------------------

-- | Handshake and transport errors.
--
--   Any error is fatal for the connection.
data Error =
    InvalidEntropy
    -- ^ ephemeral entropy is not a valid secret key
  | InvalidLength
    -- ^ input of the wrong length, or a payload over 65535 bytes
  | InvalidVersion
    -- ^ unknown handshake version
  | InvalidPub
    -- ^ invalid public key in a handshake message
  | InvalidMAC
    -- ^ authentication failed
  deriving (Eq, Show, Generic)

instance NFData Error

-- protocol constants ---------------------------------------------------------

_PROTOCOL_NAME :: BS.ByteString
_PROTOCOL_NAME = "Noise_XK_secp256k1_ChaChaPoly_SHA256"

_PROLOGUE :: BS.ByteString
_PROLOGUE = "lightning"

-- cryptographic primitives ---------------------------------------------------

-- ECDH as specified by BOLT #8: SHA256 of the compressed shared point.
--
-- 'Nothing' is unreachable for a valid secret key and a parsed point.
ecdh :: Sec -> Pub -> Maybe BS.ByteString
ecdh (Sec sec) (Pub pub) = do
  k <- Secp256k1.parse_int256 sec
  pt <- Secp256k1.mul pub k
  pure (SHA256.hash (Secp256k1.serialize_point pt))

-- h' = SHA256(h || dat)
mix_hash :: BS.ByteString -> BS.ByteString -> BS.ByteString
mix_hash h dat = SHA256.hash (h <> dat)

-- (ck', k) = HKDF(ck, ikm), with ck as salt and empty info.
--
-- HKDF limits output to 255 * hashlen bytes (8160 for SHA256), so
-- 'Nothing' is impossible for the 64 bytes requested here.
mix_key
  :: BS.ByteString
  -> BS.ByteString
  -> (BS.ByteString, BS.ByteString)
mix_key ck ikm =
  case HKDF.derive hmac ck mempty 64 ikm of
    Nothing ->
      error "ppad-bolt8: internal error, please report a bug!"
    Just output -> BS.splitAt 32 output
  where
    hmac k b = case SHA256.hmac k b of
      SHA256.MAC mac -> mac

-- ChaCha20-Poly1305 encryption, returning ciphertext || MAC.
--
-- Keys are always 32 bytes (halves of HKDF output), nonces always 12
-- bytes, and plaintexts at most 65535 bytes (far below the ChaCha20
-- counter limit), so encryption cannot fail.
encrypt_with_ad
  :: BS.ByteString -- ^ key (32 bytes)
  -> Word64        -- ^ nonce
  -> BS.ByteString -- ^ associated data
  -> BS.ByteString -- ^ plaintext
  -> BS.ByteString
encrypt_with_ad key n ad pt =
  case AEAD.encrypt ad key (encode_nonce n) pt of
    Left _ ->
      error "ppad-bolt8: internal error, please report a bug!"
    Right (ct, mac) -> ct <> mac

-- ChaCha20-Poly1305 decryption of ciphertext || MAC.
decrypt_with_ad
  :: BS.ByteString       -- ^ key (32 bytes)
  -> Word64              -- ^ nonce
  -> BS.ByteString       -- ^ associated data
  -> BS.ByteString       -- ^ ciphertext || mac
  -> Maybe BS.ByteString -- ^ plaintext
decrypt_with_ad key n ad ctmac
  | BS.length ctmac < 16 = Nothing
  | otherwise =
      let (ct, mac) = BS.splitAt (BS.length ctmac - 16) ctmac
      in  case AEAD.decrypt ad key (encode_nonce n) (ct, mac) of
            Left _   -> Nothing
            Right pt -> Just pt

-- 96-bit nonce: 4 zero bytes followed by the 64-bit nonce, little-endian
encode_nonce :: Word64 -> BS.ByteString
encode_nonce n = BS.replicate 4 0x00 <> BS.pack [
    fi n
  , fi (unsafeShiftR n 8)
  , fi (unsafeShiftR n 16)
  , fi (unsafeShiftR n 24)
  , fi (unsafeShiftR n 32)
  , fi (unsafeShiftR n 40)
  , fi (unsafeShiftR n 48)
  , fi (unsafeShiftR n 56)
  ]

-- big-endian 16-bit encoding
encode_be16 :: Word16 -> BS.ByteString
encode_be16 n = BS.pack [fi (unsafeShiftR n 8), fi n]

-- big-endian 16-bit decoding of exactly two bytes
decode_be16 :: BS.ByteString -> Maybe Word16
decode_be16 bs
  | BS.length bs /= 2 = Nothing
  | otherwise =
      let !b0 = BU.unsafeIndex bs 0
          !b1 = BU.unsafeIndex bs 1
      in  Just (fi b0 * 0x100 + fi b1)

-- handshake ------------------------------------------------------------------

-- Initial (h, ck), given the responder's static public key:
--
--   h = SHA256(protocol_name); ck = h
--   h = SHA256(h || prologue)
--   h = SHA256(h || rs.pub)
initial_state :: Pub -> (BS.ByteString, BS.ByteString)
initial_state rs =
  let !h0 = SHA256.hash _PROTOCOL_NAME
      !h1 = mix_hash h0 _PROLOGUE
      !h2 = mix_hash h1 (serialize_pub rs)
  in  (h2, h0)

-- Split a 50-byte act one or act two message into its ephemeral public
-- key and MAC, checking length and version.
parse_act :: BS.ByteString -> Either Error (BS.ByteString, BS.ByteString)
parse_act msg = do
  require (BS.length msg == 50) InvalidLength
  require (BU.unsafeHead msg == 0x00) InvalidVersion
  let !(e, c) = BS.splitAt 33 (BU.unsafeTail msg)
  pure (e, c)

-- | Initiator: produce act one (50 bytes).
--
--   Takes the local static keypair, the responder's static public key,
--   and 32 bytes of entropy for the ephemeral key. Returns act one and
--   the state for 'act3'.
--
--   The entropy is used directly as the ephemeral secret key. It must
--   be fresh, uniformly random output of a cryptographically secure
--   random source, and must never be reused. Fails with
--   'InvalidEntropy' if it is not a valid secret key.
--
--   >>> let Just i = keypair (BS.replicate 32 0x11)
--   >>> let Just r = keypair (BS.replicate 32 0x21)
--   >>> let ent = BS.replicate 32 0x12 -- use random bytes in practice
--   >>> fmap (BS.length . fst) (act1 i (keypair_pub r) ent)
--   Right 50
act1
  :: Keypair       -- ^ local static keypair
  -> Pub           -- ^ responder's static public key
  -> BS.ByteString -- ^ 32 bytes of fresh entropy
  -> Either Error (BS.ByteString, Initiator)
act1 s rs ent = do
  Keypair e_sec e_pub <- note InvalidEntropy (keypair ent)
  let !(h0, ck0) = initial_state rs
      !e_bytes = serialize_pub e_pub
      !h1 = mix_hash h0 e_bytes
  es <- note InvalidPub (ecdh e_sec rs)
  let !(ck1, temp_k1) = mix_key ck0 es
      !c = encrypt_with_ad temp_k1 0 h1 BS.empty
      !h2 = mix_hash h1 c
      !msg = BS.cons 0x00 (e_bytes <> c)
  pure (msg, Initiator h2 ck1 e_sec s rs)

-- | Responder: process act one and produce act two (50 bytes).
--
--   Takes the local static keypair, 32 bytes of entropy for the
--   ephemeral key, and act one. Returns act two and the state for
--   'finalize'.
--
--   The entropy is used directly as the ephemeral secret key. It must
--   be fresh, uniformly random output of a cryptographically secure
--   random source, and must never be reused. Fails with
--   'InvalidEntropy' if it is not a valid secret key.
--
--   Any error means the connection must be terminated.
--
--   >>> let Just i = keypair (BS.replicate 32 0x11)
--   >>> let Just r = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, _) = act1 i (keypair_pub r) (BS.replicate 32 0x12)
--   >>> fmap (BS.length . fst) (act2 r (BS.replicate 32 0x22) msg1)
--   Right 50
--   >>> fmap fst (act2 r (BS.replicate 32 0x22) (BS.take 49 msg1))
--   Left InvalidLength
act2
  :: Keypair       -- ^ local static keypair
  -> BS.ByteString -- ^ 32 bytes of fresh entropy
  -> BS.ByteString -- ^ act one
  -> Either Error (BS.ByteString, Responder)
act2 (Keypair s_sec s_pub) ent msg1 = do
  (re_bytes, c) <- parse_act msg1
  re <- note InvalidPub (parse_pub re_bytes)
  Keypair e_sec e_pub <- note InvalidEntropy (keypair ent)
  let !(h0, ck0) = initial_state s_pub
      !h1 = mix_hash h0 re_bytes
  es <- note InvalidPub (ecdh s_sec re)
  let !(ck1, temp_k1) = mix_key ck0 es
  _ <- note InvalidMAC (decrypt_with_ad temp_k1 0 h1 c)
  let !h2 = mix_hash h1 c
      !e_bytes = serialize_pub e_pub
      !h3 = mix_hash h2 e_bytes
  ee <- note InvalidPub (ecdh e_sec re)
  let !(ck2, temp_k2) = mix_key ck1 ee
      !c2 = encrypt_with_ad temp_k2 0 h3 BS.empty
      !h4 = mix_hash h3 c2
      !msg = BS.cons 0x00 (e_bytes <> c2)
  pure (msg, Responder h4 ck2 temp_k2 e_sec)

-- | Initiator: process act two and produce act three (66 bytes),
--   completing the handshake.
--
--   Any error means the connection must be terminated.
--
--   Continuing the module-level example:
--
--   >>> fmap (BS.length . fst) (act3 i_hs msg2)
--   Right 66
act3
  :: Initiator     -- ^ state from 'act1'
  -> BS.ByteString -- ^ act two
  -> Either Error (BS.ByteString, Handshake)
act3 (Initiator h ck e_sec (Keypair s_sec s_pub) rs) msg2 = do
  (re_bytes, c) <- parse_act msg2
  re <- note InvalidPub (parse_pub re_bytes)
  let !h1 = mix_hash h re_bytes
  ee <- note InvalidPub (ecdh e_sec re)
  let !(ck1, temp_k2) = mix_key ck ee
  _ <- note InvalidMAC (decrypt_with_ad temp_k2 0 h1 c)
  let !h2 = mix_hash h1 c
      !c3 = encrypt_with_ad temp_k2 1 h2 (serialize_pub s_pub)
      !h3 = mix_hash h2 c3
  se <- note InvalidPub (ecdh s_sec re)
  let !(ck2, temp_k3) = mix_key ck1 se
      !t = encrypt_with_ad temp_k3 0 h3 BS.empty
      !(sk, rk) = mix_key ck2 BS.empty
      !msg = BS.cons 0x00 (c3 <> t)
      !hs = Handshake (Sender (Cipher sk 0 ck2))
                      (Receiver (Cipher rk 0 ck2)) rs
  pure (msg, hs)

-- | Responder: process act three, completing the handshake and
--   authenticating the initiator's static public key.
--
--   Any error means the connection must be terminated.
--
--   Continuing the module-level example:
--
--   >>> let Right r_res' = finalize r_hs msg3
--   >>> handshake_remote_static r_res' == keypair_pub i
--   True
finalize
  :: Responder     -- ^ state from 'act2'
  -> BS.ByteString -- ^ act three
  -> Either Error Handshake
finalize (Responder h ck temp_k2 e_sec) msg3 = do
  require (BS.length msg3 == 66) InvalidLength
  require (BU.unsafeHead msg3 == 0x00) InvalidVersion
  let !(c, t) = BS.splitAt 49 (BU.unsafeTail msg3)
  rs_bytes <- note InvalidMAC (decrypt_with_ad temp_k2 1 h c)
  rs <- note InvalidPub (parse_pub rs_bytes)
  let !h1 = mix_hash h c
  se <- note InvalidPub (ecdh e_sec rs)
  let !(ck1, temp_k3) = mix_key ck se
  _ <- note InvalidMAC (decrypt_with_ad temp_k3 0 h1 t)
  let !(rk, sk) = mix_key ck1 BS.empty
  pure (Handshake (Sender (Cipher sk 0 ck1)) (Receiver (Cipher rk 0 ck1)) rs)

-- transport ------------------------------------------------------------------

-- Encrypt under the current key and nonce, then advance.
seal :: Cipher -> BS.ByteString -> (BS.ByteString, Cipher)
seal c@(Cipher k n _) pt =
  let !ct = encrypt_with_ad k n BS.empty pt
  in  (ct, step c)

-- Decrypt under the current key and nonce, then advance.
open :: Cipher -> BS.ByteString -> Maybe (BS.ByteString, Cipher)
open c@(Cipher k n _) ct = do
  pt <- decrypt_with_ad k n BS.empty ct
  pure (pt, step c)

-- Increment the nonce, rotating the key once it reaches 1000:
--
--   (ck', k') = HKDF(ck, k), n' = 0
step :: Cipher -> Cipher
step (Cipher k n ck)
  | n' >= 1000 =
      let !(ck', k') = mix_key ck k
      in  Cipher k' 0 ck'
  | otherwise = Cipher k n' ck
  where
    !n' = n + 1

-- | Encrypt a message of at most 65535 bytes.
--
--   Returns the frame to send (the message length plus 34 bytes) and
--   the next t'Sender', which must be used for the following message.
--   Encrypting with the same t'Sender' twice reuses a nonce and breaks
--   confidentiality and authenticity.
--
--   Fails only with 'InvalidLength', for an oversized message. Nothing
--   is encrypted in that case, so the given t'Sender' remains the
--   current one and the connection can continue.
--
--   Continuing the module-level example:
--
--   >>> fmap (BS.length . fst) (encrypt i_snd "hello")
--   Right 39
--   >>> fmap fst (encrypt i_snd (BS.replicate 65536 0x00))
--   Left InvalidLength
encrypt
  :: Sender        -- ^ current state
  -> BS.ByteString -- ^ message
  -> Either Error (BS.ByteString, Sender)
encrypt (Sender c0) m = do
  let !len = BS.length m
  require (len <= 65535) InvalidLength
  let !(lc, c1) = seal c0 (encode_be16 (fi len))
      !(bc, c2) = seal c1 m
  pure (lc <> bc, Sender c2)

-- | Decrypt a buffer holding exactly one frame.
--
--   Returns the message and the next t'Receiver'. Fails with
--   'InvalidLength' if the buffer is not exactly one frame, and with
--   'InvalidMAC' if authentication fails. Any error means the
--   connection must be terminated.
--
--   Continuing the module-level example:
--
--   >>> fmap fst (decrypt (handshake_receiver r_res) ct)
--   Right "hello"
--   >>> fmap fst (decrypt (handshake_receiver r_res) (BS.take 38 ct))
--   Left InvalidLength
decrypt
  :: Receiver      -- ^ current state
  -> BS.ByteString -- ^ one frame
  -> Either Error (BS.ByteString, Receiver)
decrypt r frame = do
  let !(lc, c) = BS.splitAt 18 frame
  (_, p) <- decrypt_header r lc
  decrypt_body p c

-- | Decrypt the 18-byte header (encrypted length and its MAC) at the
--   start of a frame.
--
--   Returns the number of bytes in the rest of the frame (the message
--   length plus a 16-byte MAC), which the caller should read exactly,
--   and the state for 'decrypt_body'. Fails with 'InvalidLength' if
--   the input is not 18 bytes, and with 'InvalidMAC' if
--   authentication fails. Any error means the connection must be
--   terminated.
--
--   Continuing the module-level example:
--
--   >>> fmap fst (decrypt_header (handshake_receiver r_res) (BS.take 18 ct))
--   Right 21
decrypt_header
  :: Receiver      -- ^ current state
  -> BS.ByteString -- ^ 18-byte header
  -> Either Error (Int, Pending)
decrypt_header (Receiver c0) lc = do
  require (BS.length lc == 18) InvalidLength
  (l, c1) <- note InvalidMAC (open c0 lc)
  len <- note InvalidLength (decode_be16 l)
  let !body = fi len + 16
  pure (body, Pending body c1)

-- | Decrypt the rest of a frame, following 'decrypt_header'.
--
--   The input must be exactly as long as 'decrypt_header' reported.
--   Returns the message and the next t'Receiver'. Fails with
--   'InvalidLength' on a length mismatch, and with 'InvalidMAC' if
--   authentication fails. Any error means the connection must be
--   terminated.
--
--   Continuing the module-level example:
--
--   >>> let (hdr, rest) = BS.splitAt 18 ct
--   >>> let Right (n, p) = decrypt_header (handshake_receiver r_res) hdr
--   >>> fmap fst (decrypt_body p (BS.take n rest))
--   Right "hello"
decrypt_body
  :: Pending       -- ^ state from 'decrypt_header'
  -> BS.ByteString -- ^ the rest of the frame
  -> Either Error (BS.ByteString, Receiver)
decrypt_body (Pending body c1) c = do
  require (BS.length c == body) InvalidLength
  (m, c2) <- note InvalidMAC (open c1 c)
  pure (m, Receiver c2)

-- utilities ------------------------------------------------------------------

-- lowercase hex encoding
hex :: BS.ByteString -> String
hex = BS.foldr (\w acc -> nibble (unsafeShiftR w 4) : nibble (w .&. 15) : acc)
  []
  where
    nibble :: Word8 -> Char
    nibble n
      | n < 10    = toEnum (fi n + 0x30)
      | otherwise = toEnum (fi n + 0x57)

note :: e -> Maybe a -> Either e a
note e = maybe (Left e) Right
{-# INLINE note #-}

require :: Bool -> e -> Either e ()
require cond e = unless cond (Left e)
{-# INLINE require #-}

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}
