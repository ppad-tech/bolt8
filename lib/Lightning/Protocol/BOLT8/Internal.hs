{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Lightning.Protocol.BOLT8.Internal
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Internal module exporting all constructors for testing and
-- benchmarking. Prefer "Lightning.Protocol.BOLT8" for general use.

module Lightning.Protocol.BOLT8.Internal (
    -- * Keys
    Sec(..)
  , Pub(..)
  , keypair
  , parse_pub
  , serialize_pub

    -- * Newtypes
  , Key32(..)
  , key32
  , unsafeKey32
  , SessionNonce(..)
  , MessagePayload(..)
  , mkMessagePayload

    -- * Handshake roles
  , Initiator
  , Responder
  , HandshakeFor(..)

    -- * Handshake (initiator)
  , act1
  , act3

    -- * Handshake (responder)
  , act2
  , finalize

    -- * Session
  , Session(..)
  , HandshakeState(..)
  , Handshake(..)
  , encrypt
  , decrypt
  , decrypt_frame
  , decrypt_frame_partial
  , FrameResult(..)

    -- * Errors
  , Error(..)
  ) where

import Control.Monad (guard, unless)
import qualified Crypto.AEAD.ChaCha20Poly1305 as AEAD
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.KDF.HMAC as HKDF
import Data.Bits (unsafeShiftR, (.&.))
import qualified Data.ByteString as BS
import Data.Word (Word16, Word64)
import GHC.Generics (Generic)

-- types -----------------------------------------------------------

-- | Secret key (32 bytes).
newtype Sec = Sec BS.ByteString
  deriving (Eq, Generic)

-- | Compressed public key.
newtype Pub = Pub Secp256k1.Projective

instance Eq Pub where
  (Pub a) == (Pub b) =
    Secp256k1.serialize_point a
      == Secp256k1.serialize_point b

instance Show Pub where
  show (Pub p) =
    "Pub " ++ show (Secp256k1.serialize_point p)

-- | A 32-byte key, validated at construction.
newtype Key32 = Key32 { unKey32 :: BS.ByteString }
  deriving (Eq, Generic)

-- | Construct a 'Key32' from a 32-byte 'BS.ByteString'.
--
--   Returns 'Nothing' if the input is not exactly 32 bytes.
--
--   >>> key32 (BS.replicate 32 0x00)
--   Just (Key32 {unKey32 = ...})
--   >>> key32 (BS.replicate 31 0x00)
--   Nothing
key32 :: BS.ByteString -> Maybe Key32
key32 bs
  | BS.length bs == 32 = Just (Key32 bs)
  | otherwise = Nothing

-- | Construct a 'Key32' without validation.
--
--   For test and benchmark use only; prefer 'key32'.
unsafeKey32 :: BS.ByteString -> Key32
unsafeKey32 = Key32

-- | Session nonce, distinguishing send from receive direction.
newtype SessionNonce =
  SessionNonce { unSessionNonce :: Word64 }
  deriving (Eq, Generic)

-- | Message payload (max 65535 bytes), validated at construction.
newtype MessagePayload =
  MessagePayload { unMessagePayload :: BS.ByteString }
  deriving (Eq, Generic)

-- | Construct a 'MessagePayload' from a 'BS.ByteString'.
--
--   Returns 'Left' if the payload exceeds 65535 bytes.
mkMessagePayload
  :: BS.ByteString -> Either Error MessagePayload
mkMessagePayload bs
  | BS.length bs > 65535 = Left InvalidLength
  | otherwise = Right (MessagePayload bs)

-- | Handshake errors.
data Error =
    InvalidKey
  | InvalidPub
  | InvalidMAC
  | InvalidVersion
  | InvalidLength
  | DecryptionFailed
  deriving (Eq, Show, Generic)

-- | Result of attempting to decrypt a frame from a partial
--   buffer.
data FrameResult =
    NeedMore {-# UNPACK #-} !Int
    -- ^ More bytes needed; the 'Int' is the minimum
    --   additional bytes required.
  | FrameOk !BS.ByteString !BS.ByteString !Session
    -- ^ Successfully decrypted: plaintext, remainder,
    --   updated session.
  | FrameError !Error
    -- ^ Decryption failed with the given error.
  deriving Generic

-- | Post-handshake session state.
data Session = Session {
    sess_sk  :: !Key32
    -- ^ send key (32 bytes)
  , sess_sn  :: !SessionNonce
    -- ^ send nonce
  , sess_sck :: !Key32
    -- ^ send chaining key
  , sess_rk  :: !Key32
    -- ^ receive key (32 bytes)
  , sess_rn  :: !SessionNonce
    -- ^ receive nonce
  , sess_rck :: !Key32
    -- ^ receive chaining key
  }
  deriving Generic

-- | Result of a successful handshake.
data Handshake = Handshake {
    session       :: !Session
    -- ^ session state
  , remote_static :: !Pub
    -- ^ authenticated remote static pubkey
  }
  deriving Generic

-- | Internal handshake state (exported for benchmarking).
data HandshakeState = HandshakeState {
    hs_h      :: {-# UNPACK #-} !BS.ByteString
    -- ^ handshake hash (32 bytes)
  , hs_ck     :: {-# UNPACK #-} !BS.ByteString
    -- ^ chaining key (32 bytes)
  , hs_temp_k :: {-# UNPACK #-} !BS.ByteString
    -- ^ temp key (32 bytes)
  , hs_e_sec  :: !Sec
    -- ^ ephemeral secret
  , hs_e_pub  :: !Pub
    -- ^ ephemeral public
  , hs_s_sec  :: !Sec
    -- ^ static secret
  , hs_s_pub  :: !Pub
    -- ^ static public
  , hs_re     :: !(Maybe Pub)
    -- ^ remote ephemeral
  , hs_rs     :: !(Maybe Pub)
    -- ^ remote static
  }
  deriving Generic

-- handshake roles -------------------------------------------------

-- | Phantom type for initiator role.
data Initiator

-- | Phantom type for responder role.
data Responder

-- | Role-indexed handshake state.
--
--   The phantom type parameter prevents passing an initiator's
--   state to a responder function and vice versa.
data HandshakeFor a =
  HandshakeFor { unHandshakeFor :: !HandshakeState }

-- protocol constants ----------------------------------------------

_PROTOCOL_NAME :: BS.ByteString
_PROTOCOL_NAME =
  "Noise_XK_secp256k1_ChaChaPoly_SHA256"

_PROLOGUE :: BS.ByteString
_PROLOGUE = "lightning"

-- key operations --------------------------------------------------

-- | Derive a keypair from 32 bytes of entropy.
--
--   Returns Nothing if the entropy is invalid
--   (zero or >= curve order).
--
--   >>> let ent = BS.replicate 32 0x11
--   >>> case keypair ent of
--   ...   Just _ -> "ok"
--   ...   Nothing -> "fail"
--   "ok"
--   >>> keypair (BS.replicate 31 0x11) -- wrong length
--   Nothing
keypair :: BS.ByteString -> Maybe (Sec, Pub)
keypair ent = do
  guard (BS.length ent == 32)
  k <- Secp256k1.parse_int256 ent
  p <- Secp256k1.derive_pub k
  pure (Sec ent, Pub p)

-- | Parse a 33-byte compressed public key.
--
--   >>> let Just (_, pub) = keypair (BS.replicate 32 0x11)
--   >>> let bytes = serialize_pub pub
--   >>> case parse_pub bytes of
--   ...   Just _ -> "ok"
--   ...   Nothing -> "fail"
--   "ok"
--   >>> parse_pub (BS.replicate 32 0x00) -- wrong length
--   Nothing
parse_pub :: BS.ByteString -> Maybe Pub
parse_pub bs = do
  guard (BS.length bs == 33)
  p <- Secp256k1.parse_point bs
  pure (Pub p)

-- | Serialize a public key to 33-byte compressed form.
--
--   >>> let Just (_, pub) = keypair (BS.replicate 32 0x11)
--   >>> BS.length (serialize_pub pub)
--   33
serialize_pub :: Pub -> BS.ByteString
serialize_pub (Pub p) = Secp256k1.serialize_point p

-- cryptographic primitives ----------------------------------------

-- bolt8-style ECDH
ecdh :: Sec -> Pub -> Maybe BS.ByteString
ecdh (Sec sec) (Pub pub) = do
  k <- Secp256k1.parse_int256 sec
  pt <- Secp256k1.mul pub k
  let compressed = Secp256k1.serialize_point pt
  pure (SHA256.hash compressed)

-- h' = SHA256(h || data)
mix_hash
  :: BS.ByteString -> BS.ByteString -> BS.ByteString
mix_hash h dat = SHA256.hash (h <> dat)

-- Mix key: (ck', k) = HKDF(ck, input_key_material)
--
-- NB HKDF limits output to 255 * hashlen bytes. For SHA256
-- that's 8160, well above the 64 bytes requested here, so
-- 'Nothing' is impossible.
mix_key
  :: BS.ByteString
  -> BS.ByteString
  -> (BS.ByteString, BS.ByteString)
mix_key ck ikm =
  case HKDF.derive hmac ck mempty 64 ikm of
    Nothing ->
      error
        "ppad-bolt8: internal error, please report a bug!"
    Just output -> BS.splitAt 32 output
  where
    hmac k b = case SHA256.hmac k b of
      SHA256.MAC mac -> mac

-- Encrypt with associated data using ChaCha20-Poly1305
encrypt_with_ad
  :: BS.ByteString       -- ^ key (32 bytes)
  -> Word64              -- ^ nonce
  -> BS.ByteString       -- ^ associated data
  -> BS.ByteString       -- ^ plaintext
  -> Maybe BS.ByteString -- ^ ciphertext || mac (16 bytes)
encrypt_with_ad key n ad pt =
  case AEAD.encrypt ad key (encode_nonce n) pt of
    Left _ -> Nothing
    Right (ct, mac) -> Just (ct <> mac)

-- Decrypt with associated data using ChaCha20-Poly1305
decrypt_with_ad
  :: BS.ByteString       -- ^ key (32 bytes)
  -> Word64              -- ^ nonce
  -> BS.ByteString       -- ^ associated data
  -> BS.ByteString       -- ^ ciphertext || mac
  -> Maybe BS.ByteString -- ^ plaintext
decrypt_with_ad key n ad ctmac
  | BS.length ctmac < 16 = Nothing
  | otherwise =
      let (ct, mac) =
            BS.splitAt (BS.length ctmac - 16) ctmac
      in case AEAD.decrypt ad key (encode_nonce n)
                (ct, mac) of
           Left _ -> Nothing
           Right pt -> Just pt

-- Encode nonce as 96-bit value: 4 zero bytes + 8-byte LE
encode_nonce :: Word64 -> BS.ByteString
encode_nonce n = BS.replicate 4 0x00 <> encode_le64 n

-- Little-endian 64-bit encoding
encode_le64 :: Word64 -> BS.ByteString
encode_le64 n = BS.pack [
    fi (n .&. 0xff)
  , fi (unsafeShiftR n 8  .&. 0xff)
  , fi (unsafeShiftR n 16 .&. 0xff)
  , fi (unsafeShiftR n 24 .&. 0xff)
  , fi (unsafeShiftR n 32 .&. 0xff)
  , fi (unsafeShiftR n 40 .&. 0xff)
  , fi (unsafeShiftR n 48 .&. 0xff)
  , fi (unsafeShiftR n 56 .&. 0xff)
  ]

-- Big-endian 16-bit encoding
encode_be16 :: Word16 -> BS.ByteString
encode_be16 n =
  BS.pack [fi (unsafeShiftR n 8), fi (n .&. 0xff)]

-- Big-endian 16-bit decoding
decode_be16 :: BS.ByteString -> Maybe Word16
decode_be16 bs
  | BS.length bs /= 2 = Nothing
  | otherwise =
      let !b0 = BS.index bs 0
          !b1 = BS.index bs 1
      in Just (fi b0 * 0x100 + fi b1)

-- handshake -------------------------------------------------------

-- Initialize handshake state
--
-- h = SHA256(protocol_name)
-- ck = h
-- h = SHA256(h || prologue)
-- h = SHA256(h || responder_static_pubkey)
init_handshake
  :: Sec           -- ^ local static secret
  -> Pub           -- ^ local static public
  -> Sec           -- ^ ephemeral secret
  -> Pub           -- ^ ephemeral public
  -> Maybe Pub     -- ^ remote static
  -> Bool          -- ^ True if initiator
  -> HandshakeState
init_handshake s_sec s_pub e_sec e_pub m_rs is_init =
  let !h0 = SHA256.hash _PROTOCOL_NAME
      !ck = h0
      !h1 = mix_hash h0 _PROLOGUE
      -- Mix in responder's static pubkey
      !h2 = case (is_init, m_rs) of
        (True, Just rs) ->
          mix_hash h1 (serialize_pub rs)
        (False, Nothing) ->
          mix_hash h1 (serialize_pub s_pub)
        _ -> h1  -- shouldn't happen
  in HandshakeState {
       hs_h      = h2
     , hs_ck     = ck
     , hs_temp_k = BS.replicate 32 0x00
     , hs_e_sec  = e_sec
     , hs_e_pub  = e_pub
     , hs_s_sec  = s_sec
     , hs_s_pub  = s_pub
     , hs_re     = Nothing
     , hs_rs     = m_rs
     }

-- | Initiator: generate Act 1 message (50 bytes).
--
--   Takes local static key, remote static pubkey, and 32
--   bytes of entropy for ephemeral key generation.
--
--   Returns the 50-byte Act 1 message and handshake state
--   for Act 3.
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let eph_ent = BS.replicate 32 0x12
--   >>> case act1 i_sec i_pub r_pub eph_ent of { Right (msg, _) -> BS.length msg; Left _ -> 0 }
--   50
act1
  :: Sec
  -> Pub
  -> Pub
  -> BS.ByteString
  -> Either Error
       (BS.ByteString, HandshakeFor Initiator)
act1 s_sec s_pub rs ent = do
  (e_sec, e_pub) <- note InvalidKey (keypair ent)
  let !hs0 = init_handshake
               s_sec s_pub e_sec e_pub (Just rs) True
      !e_pub_bytes = serialize_pub e_pub
      !h1 = mix_hash (hs_h hs0) e_pub_bytes
  es <- note InvalidKey (ecdh e_sec rs)
  let !(ck1, temp_k1) = mix_key (hs_ck hs0) es
  c <- note InvalidMAC
         (encrypt_with_ad temp_k1 0 h1 BS.empty)
  let !h2 = mix_hash h1 c
      !msg = BS.singleton 0x00 <> e_pub_bytes <> c
      !hs1 = hs0 {
        hs_h      = h2
      , hs_ck     = ck1
      , hs_temp_k = temp_k1
      }
  pure (msg, HandshakeFor hs1)

-- | Responder: process Act 1 and generate Act 2 message
--   (50 bytes).
--
--   Takes local static key and 32 bytes of entropy for
--   ephemeral key, plus the 50-byte Act 1 message from
--   initiator.
--
--   Returns the 50-byte Act 2 message and handshake state
--   for finalize.
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, _) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> case act2 r_sec r_pub (BS.replicate 32 0x22) msg1 of { Right (msg, _) -> BS.length msg; Left _ -> 0 }
--   50
act2
  :: Sec
  -> Pub
  -> BS.ByteString
  -> BS.ByteString
  -> Either Error
       (BS.ByteString, HandshakeFor Responder)
act2 s_sec s_pub ent msg1 = do
  require (BS.length msg1 == 50) InvalidLength
  let !version = BS.index msg1 0
      !re_bytes = BS.take 33 (BS.drop 1 msg1)
      !c = BS.drop 34 msg1
  require (version == 0x00) InvalidVersion
  re <- note InvalidPub (parse_pub re_bytes)
  (e_sec, e_pub) <- note InvalidKey (keypair ent)
  let !hs0 = init_handshake
               s_sec s_pub e_sec e_pub Nothing False
      !h1 = mix_hash (hs_h hs0) re_bytes
  es <- note InvalidKey (ecdh s_sec re)
  let !(ck1, temp_k1) = mix_key (hs_ck hs0) es
  _ <- note InvalidMAC
         (decrypt_with_ad temp_k1 0 h1 c)
  let !h2 = mix_hash h1 c
      !e_pub_bytes = serialize_pub e_pub
      !h3 = mix_hash h2 e_pub_bytes
  ee <- note InvalidKey (ecdh e_sec re)
  let !(ck2, temp_k2) = mix_key ck1 ee
  c2 <- note InvalidMAC
          (encrypt_with_ad temp_k2 0 h3 BS.empty)
  let !h4 = mix_hash h3 c2
      !msg = BS.singleton 0x00 <> e_pub_bytes <> c2
      !hs1 = hs0 {
        hs_h      = h4
      , hs_ck     = ck2
      , hs_temp_k = temp_k2
      , hs_re     = Just re
      }
  pure (msg, HandshakeFor hs1)

-- | Initiator: process Act 2 and generate Act 3 (66 bytes),
--   completing the handshake.
--
--   Returns the 66-byte Act 3 message and the handshake
--   result.
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, i_hs) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> let Right (msg2, _) = act2 r_sec r_pub (BS.replicate 32 0x22) msg1
--   >>> case act3 i_hs msg2 of { Right (msg, _) -> BS.length msg; Left _ -> 0 }
--   66
act3
  :: HandshakeFor Initiator
  -> BS.ByteString
  -> Either Error (BS.ByteString, Handshake)
act3 (HandshakeFor hs) msg2 = do
  require (BS.length msg2 == 50) InvalidLength
  let !version = BS.index msg2 0
      !re_bytes = BS.take 33 (BS.drop 1 msg2)
      !c = BS.drop 34 msg2
  require (version == 0x00) InvalidVersion
  re <- note InvalidPub (parse_pub re_bytes)
  let !h1 = mix_hash (hs_h hs) re_bytes
  ee <- note InvalidKey (ecdh (hs_e_sec hs) re)
  let !(ck1, temp_k2) = mix_key (hs_ck hs) ee
  _ <- note InvalidMAC
         (decrypt_with_ad temp_k2 0 h1 c)
  let !h2 = mix_hash h1 c
      !s_pub_bytes = serialize_pub (hs_s_pub hs)
  c3 <- note InvalidMAC
          (encrypt_with_ad temp_k2 1 h2 s_pub_bytes)
  let !h3 = mix_hash h2 c3
  se <- note InvalidKey (ecdh (hs_s_sec hs) re)
  let !(ck2, temp_k3) = mix_key ck1 se
  t <- note InvalidMAC
         (encrypt_with_ad temp_k3 0 h3 BS.empty)
  let !(sk, rk) = mix_key ck2 BS.empty
      !msg = BS.singleton 0x00 <> c3 <> t
      !sess = Session {
        sess_sk  = Key32 sk
      , sess_sn  = SessionNonce 0
      , sess_sck = Key32 ck2
      , sess_rk  = Key32 rk
      , sess_rn  = SessionNonce 0
      , sess_rck = Key32 ck2
      }
  rs <- note InvalidPub (hs_rs hs)
  let !result = Handshake {
        session       = sess
      , remote_static = rs
      }
  pure (msg, result)

-- | Responder: process Act 3 (66 bytes) and complete the
--   handshake.
--
--   Returns the handshake result with authenticated remote
--   static pubkey.
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, i_hs) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> let Right (msg2, r_hs) = act2 r_sec r_pub (BS.replicate 32 0x22) msg1
--   >>> let Right (msg3, _) = act3 i_hs msg2
--   >>> case finalize r_hs msg3 of { Right _ -> "ok"; Left e -> show e }
--   "ok"
finalize
  :: HandshakeFor Responder
  -> BS.ByteString
  -> Either Error Handshake
finalize (HandshakeFor hs) msg3 = do
  require (BS.length msg3 == 66) InvalidLength
  let !version = BS.index msg3 0
      !c = BS.take 49 (BS.drop 1 msg3)
      !t = BS.drop 50 msg3
  require (version == 0x00) InvalidVersion
  rs_bytes <- note InvalidMAC
    (decrypt_with_ad (hs_temp_k hs) 1 (hs_h hs) c)
  rs <- note InvalidPub (parse_pub rs_bytes)
  let !h1 = mix_hash (hs_h hs) c
  se <- note InvalidKey (ecdh (hs_e_sec hs) rs)
  let !(ck1, temp_k3) = mix_key (hs_ck hs) se
  _ <- note InvalidMAC
         (decrypt_with_ad temp_k3 0 h1 t)
  -- responder swaps order (receives what initiator sends)
  let !(rk, sk) = mix_key ck1 BS.empty
      !sess = Session {
        sess_sk  = Key32 sk
      , sess_sn  = SessionNonce 0
      , sess_sck = Key32 ck1
      , sess_rk  = Key32 rk
      , sess_rn  = SessionNonce 0
      , sess_rck = Key32 ck1
      }
      !result = Handshake {
        session       = sess
      , remote_static = rs
      }
  pure result

-- message encryption ----------------------------------------------

-- | Encrypt a message (max 65535 bytes).
--
--   Returns the encrypted packet and updated session. Key
--   rotation is handled automatically at nonce 1000.
--
--   Wire format:
--     encrypted_length (2) || MAC (16)
--     || encrypted_body || MAC (16)
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, i_hs) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> let Right (msg2, _) = act2 r_sec r_pub (BS.replicate 32 0x22) msg1
--   >>> let Right (_, i_result) = act3 i_hs msg2
--   >>> let sess = session i_result
--   >>> case encrypt sess "hello" of { Right (ct, _) -> BS.length ct; Left _ -> 0 }
--   39
encrypt
  :: Session
  -> BS.ByteString
  -> Either Error (BS.ByteString, Session)
encrypt sess pt = do
  let !len = BS.length pt
  require (len <= 65535) InvalidLength
  let !len_bytes = encode_be16 (fi len)
      !sk = unKey32 (sess_sk sess)
      !sn = unSessionNonce (sess_sn sess)
      !sck = unKey32 (sess_sck sess)
  lc <- note InvalidMAC
          (encrypt_with_ad sk sn BS.empty len_bytes)
  let !(sn1, sck1, sk1) = step_nonce sn sck sk
  bc <- note InvalidMAC
          (encrypt_with_ad sk1 sn1 BS.empty pt)
  let !(sn2, sck2, sk2) = step_nonce sn1 sck1 sk1
      !packet = lc <> bc
      !sess' = sess {
        sess_sk  = Key32 sk2
      , sess_sn  = SessionNonce sn2
      , sess_sck = Key32 sck2
      }
  pure (packet, sess')

-- | Decrypt a message, requiring an exact packet with no
--   trailing bytes.
--
--   Returns the plaintext and updated session. Key rotation
--   is handled automatically at nonce 1000.
--
--   This is a strict variant that rejects any trailing data.
--   For streaming use cases where you need to handle multiple
--   frames in a buffer, use 'decrypt_frame' instead.
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, i_hs) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> let Right (msg2, r_hs) = act2 r_sec r_pub (BS.replicate 32 0x22) msg1
--   >>> let Right (msg3, i_result) = act3 i_hs msg2
--   >>> let Right r_result = finalize r_hs msg3
--   >>> let Right (ct, _) = encrypt (session i_result) "hello"
--   >>> case decrypt (session r_result) ct of { Right (pt, _) -> pt; Left _ -> "fail" }
--   "hello"
decrypt
  :: Session
  -> BS.ByteString
  -> Either Error (BS.ByteString, Session)
decrypt sess packet = do
  (pt, remainder, sess') <- decrypt_frame sess packet
  require (BS.null remainder) InvalidLength
  pure (pt, sess')

-- | Decrypt a single frame from a buffer, returning the
--   remainder.
--
--   Returns the plaintext, any unconsumed bytes, and the
--   updated session. Key rotation is handled automatically
--   every 1000 messages.
--
--   This is useful for streaming scenarios where multiple
--   messages may be buffered together. The remainder can be
--   passed to the next call to 'decrypt_frame'.
--
--   Wire format consumed:
--     encrypted_length (18) || encrypted_body (len + 16)
--
--   >>> let Just (i_sec, i_pub) = keypair (BS.replicate 32 0x11)
--   >>> let Just (r_sec, r_pub) = keypair (BS.replicate 32 0x21)
--   >>> let Right (msg1, i_hs) = act1 i_sec i_pub r_pub (BS.replicate 32 0x12)
--   >>> let Right (msg2, r_hs) = act2 r_sec r_pub (BS.replicate 32 0x22) msg1
--   >>> let Right (msg3, i_result) = act3 i_hs msg2
--   >>> let Right r_result = finalize r_hs msg3
--   >>> let Right (ct, _) = encrypt (session i_result) "hello"
--   >>> case decrypt_frame (session r_result) ct of { Right (pt, rem, _) -> (pt, BS.null rem); Left _ -> ("fail", False) }
--   ("hello",True)
decrypt_frame
  :: Session
  -> BS.ByteString
  -> Either Error
       (BS.ByteString, BS.ByteString, Session)
decrypt_frame sess packet = do
  require (BS.length packet >= 34) InvalidLength
  let !lc = BS.take 18 packet
      !rest = BS.drop 18 packet
      !rk = unKey32 (sess_rk sess)
      !rn = unSessionNonce (sess_rn sess)
      !rck = unKey32 (sess_rck sess)
  len_bytes <- note InvalidMAC
    (decrypt_with_ad rk rn BS.empty lc)
  len <- note InvalidLength (decode_be16 len_bytes)
  let !(rn1, rck1, rk1) = step_nonce rn rck rk
      !body_len = fi len + 16
  require (BS.length rest >= body_len) InvalidLength
  let !bc = BS.take body_len rest
      !remainder = BS.drop body_len rest
  pt <- note InvalidMAC
          (decrypt_with_ad rk1 rn1 BS.empty bc)
  let !(rn2, rck2, rk2) = step_nonce rn1 rck1 rk1
      !sess' = sess {
        sess_rk  = Key32 rk2
      , sess_rn  = SessionNonce rn2
      , sess_rck = Key32 rck2
      }
  pure (pt, remainder, sess')

-- | Decrypt a frame from a partial buffer, indicating when
--   more data needed.
--
--   Unlike 'decrypt_frame', this function handles incomplete
--   buffers gracefully by returning 'NeedMore' with the
--   number of additional bytes required to make progress.
--
--   * If the buffer has fewer than 18 bytes (encrypted
--     length + MAC), returns @'NeedMore' n@ where @n@ is
--     the bytes still needed.
--   * If the length header is complete but the body is
--     incomplete, returns @'NeedMore' n@ with bytes needed
--     for the full frame.
--   * MAC or decryption failures return 'FrameError'.
--   * A complete, valid frame returns 'FrameOk' with
--     plaintext, remainder, and updated session.
--
--   This is useful for non-blocking I/O where data arrives
--   incrementally.
decrypt_frame_partial
  :: Session
  -> BS.ByteString
  -> FrameResult
decrypt_frame_partial sess buf
  | buflen < 18 = NeedMore (18 - buflen)
  | otherwise =
      let !lc = BS.take 18 buf
          !rest = BS.drop 18 buf
          !rk = unKey32 (sess_rk sess)
          !rn = unSessionNonce (sess_rn sess)
          !rck = unKey32 (sess_rck sess)
      in case decrypt_with_ad rk rn BS.empty lc of
           Nothing -> FrameError InvalidMAC
           Just len_bytes ->
             case decode_be16 len_bytes of
               Nothing -> FrameError InvalidLength
               Just len ->
                 let !body_len = fi len + 16
                     !(rn1, rck1, rk1) =
                       step_nonce rn rck rk
                 in if BS.length rest < body_len
                   then NeedMore
                     (body_len - BS.length rest)
                   else
                     let !bc = BS.take body_len rest
                         !remainder =
                           BS.drop body_len rest
                     in case decrypt_with_ad
                              rk1 rn1 BS.empty bc of
                       Nothing ->
                         FrameError InvalidMAC
                       Just pt ->
                         let !(rn2, rck2, rk2) =
                               step_nonce rn1 rck1 rk1
                             !sess' = sess {
                               sess_rk  = Key32 rk2
                             , sess_rn  =
                                 SessionNonce rn2
                             , sess_rck = Key32 rck2
                             }
                         in FrameOk pt remainder sess'
  where
    !buflen = BS.length buf

-- key rotation ----------------------------------------------------

-- Key rotation occurs after nonce reaches 1000 (i.e., before
-- using 1000)
-- (ck', k') = HKDF(ck, k), reset nonce to 0
step_nonce
  :: Word64
  -> BS.ByteString
  -> BS.ByteString
  -> (Word64, BS.ByteString, BS.ByteString)
step_nonce n ck k
  | n + 1 == 1000 =
      let !(ck', k') = mix_key ck k
      in (0, ck', k')
  | otherwise = (n + 1, ck, k)

-- utilities -------------------------------------------------------

-- Lift Maybe to Either
note :: e -> Maybe a -> Either e a
note e = maybe (Left e) Right
{-# INLINE note #-}

-- Require condition or fail
require :: Bool -> e -> Either e ()
require cond e = unless cond (Left e)
{-# INLINE require #-}

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}
