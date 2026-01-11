{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Module: Lightning.Protocol.BOLT8
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
--  Encrypted and authenticated transport, per
--  [BOLT #8](https://github.com/lightning/bolts/blob/master/08-transport.md).
--
-- This module implements the Noise_XK_secp256k1_ChaChaPoly_SHA256
-- handshake protocol for Lightning Network transport encryption.

module Lightning.Protocol.BOLT8 (
    -- * Keys
    Sec
  , Pub
  , keypair
  , parse_pub
  , serialize_pub

    -- * Handshake (initiator)
  , initiator_act1
  , initiator_act3

    -- * Handshake (responder)
  , responder_act2
  , responder_finalize

    -- * Session
  , Session
  , HandshakeResult(..)
  , encrypt_message
  , decrypt_message

    -- * Errors
  , Error(..)
  ) where

import Control.Monad (guard)
import qualified Crypto.AEAD.ChaCha20Poly1305 as AEAD
import qualified Crypto.Curve.Secp256k1 as Secp256k1
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.KDF.HMAC as HKDF
import qualified Data.ByteString as BS
import Data.Word (Word16, Word64)

-- types ---------------------------------------------------------------------

-- | Secret key (32 bytes).
newtype Sec = Sec BS.ByteString
  deriving Eq

-- | Compressed public key.
newtype Pub = Pub Secp256k1.Projective

instance Eq Pub where
  (Pub a) == (Pub b) =
    Secp256k1.serialize_point a == Secp256k1.serialize_point b

instance Show Pub where
  show (Pub p) = "Pub " ++ show (Secp256k1.serialize_point p)

-- | Handshake errors.
data Error =
    InvalidKey
  | InvalidPub
  | InvalidMAC
  | InvalidVersion
  | InvalidLength
  | DecryptionFailed
  deriving (Eq, Show)

-- | Post-handshake session state.
data Session = Session {
    sess_sk  :: {-# UNPACK #-} !BS.ByteString  -- ^ send key (32 bytes)
  , sess_sn  :: {-# UNPACK #-} !Word64         -- ^ send nonce
  , sess_sck :: {-# UNPACK #-} !BS.ByteString  -- ^ send chaining key
  , sess_rk  :: {-# UNPACK #-} !BS.ByteString  -- ^ receive key (32 bytes)
  , sess_rn  :: {-# UNPACK #-} !Word64         -- ^ receive nonce
  , sess_rck :: {-# UNPACK #-} !BS.ByteString  -- ^ receive chaining key
  }

-- | Result of a successful handshake.
data HandshakeResult = HandshakeResult {
    hr_session   :: !Session      -- ^ session state
  , hr_remote_pk :: !Pub          -- ^ authenticated remote static pubkey
  }

-- internal handshake state
data HandshakeState = HandshakeState {
    hs_h      :: {-# UNPACK #-} !BS.ByteString  -- handshake hash (32 bytes)
  , hs_ck     :: {-# UNPACK #-} !BS.ByteString  -- chaining key (32 bytes)
  , hs_temp_k :: {-# UNPACK #-} !BS.ByteString  -- temp key (32 bytes)
  , hs_e_sec  :: !Sec                           -- ephemeral secret
  , hs_e_pub  :: !Pub                           -- ephemeral public
  , hs_s_sec  :: !Sec                           -- static secret
  , hs_s_pub  :: !Pub                           -- static public
  , hs_re     :: !(Maybe Pub)                   -- remote ephemeral
  , hs_rs     :: !(Maybe Pub)                   -- remote static
  }

-- protocol constants --------------------------------------------------------

_PROTOCOL_NAME :: BS.ByteString
_PROTOCOL_NAME = "Noise_XK_secp256k1_ChaChaPoly_SHA256"

_PROLOGUE :: BS.ByteString
_PROLOGUE = "lightning"

-- key operations ------------------------------------------------------------

-- | Derive a keypair from 32 bytes of entropy.
--
--   Returns Nothing if the entropy is invalid (zero or >= curve order).
keypair :: BS.ByteString -> Maybe (Sec, Pub)
keypair ent = do
  guard (BS.length ent == 32)
  k <- Secp256k1.parse_int256 ent
  p <- Secp256k1.derive_pub k
  pure (Sec ent, Pub p)

-- | Parse a 33-byte compressed public key.
parse_pub :: BS.ByteString -> Maybe Pub
parse_pub bs = do
  guard (BS.length bs == 33)
  p <- Secp256k1.parse_point bs
  pure (Pub p)

-- | Serialize a public key to 33-byte compressed form.
serialize_pub :: Pub -> BS.ByteString
serialize_pub (Pub p) = Secp256k1.serialize_point p

-- cryptographic primitives --------------------------------------------------

-- bolt8-style ECDH
ecdh :: Sec -> Pub -> Maybe BS.ByteString
ecdh (Sec sec) (Pub pub) = do
  k <- Secp256k1.parse_int256 sec
  pt <- Secp256k1.mul pub k
  let compressed = Secp256k1.serialize_point pt
  pure (SHA256.hash compressed)

-- h' = SHA256(h || data)
mix_hash :: BS.ByteString -> BS.ByteString -> BS.ByteString
mix_hash h dat = SHA256.hash (h <> dat)

-- Mix key: (ck', k) = HKDF(ck, input_key_material)
mix_key :: BS.ByteString -> BS.ByteString -> (BS.ByteString, BS.ByteString)
mix_key ck ikm = case HKDF.derive hmac ck mempty 64 ikm of
    Nothing -> error "ppad-bolt8: internal error, please report a bug!"
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
      let (ct, mac) = BS.splitAt (BS.length ctmac - 16) ctmac
      in case AEAD.decrypt ad key (encode_nonce n) (ct, mac) of
           Left _ -> Nothing
           Right pt -> Just pt

-- Encode nonce as 96-bit value: 4 zero bytes + 8-byte little-endian
encode_nonce :: Word64 -> BS.ByteString
encode_nonce n = BS.replicate 4 0x00 <> encode_le64 n

-- Little-endian 64-bit encoding
encode_le64 :: Word64 -> BS.ByteString
encode_le64 n = BS.pack [
    fi n
  , fi (n `div` 0x100)
  , fi (n `div` 0x10000)
  , fi (n `div` 0x1000000)
  , fi (n `div` 0x100000000)
  , fi (n `div` 0x10000000000)
  , fi (n `div` 0x1000000000000)
  , fi (n `div` 0x100000000000000)
  ]

-- Big-endian 16-bit encoding
encode_be16 :: Word16 -> BS.ByteString
encode_be16 n = BS.pack [fi (n `div` 0x100), fi n]

-- Big-endian 16-bit decoding
decode_be16 :: BS.ByteString -> Maybe Word16
decode_be16 bs
  | BS.length bs /= 2 = Nothing
  | otherwise =
      let !b0 = BS.index bs 0
          !b1 = BS.index bs 1
      in Just (fi b0 * 0x100 + fi b1)

-- handshake -----------------------------------------------------------------

-- Initialize handshake state
--
-- h = SHA256(protocol_name)
-- ck = h
-- h = SHA256(h || prologue)
-- h = SHA256(h || responder_static_pubkey)
init_handshake
  :: Sec                -- ^ local static secret
  -> Pub                -- ^ local static public
  -> Sec                -- ^ ephemeral secret
  -> Pub                -- ^ ephemeral public
  -> Maybe Pub          -- ^ remote static (initiator knows, responder doesn't)
  -> Bool               -- ^ True if initiator
  -> HandshakeState
init_handshake s_sec s_pub e_sec e_pub m_rs is_initiator =
  let !h0 = SHA256.hash _PROTOCOL_NAME
      !ck = h0
      !h1 = mix_hash h0 _PROLOGUE
      -- Mix in responder's static pubkey
      !h2 = case (is_initiator, m_rs) of
        (True, Just rs)  -> mix_hash h1 (serialize_pub rs)
        (False, Nothing) -> mix_hash h1 (serialize_pub s_pub)
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
--   Takes local static key, remote static pubkey, and 32 bytes of
--   entropy for ephemeral key generation.
--
--   Returns the 50-byte Act 1 message and handshake state for Act 3.
initiator_act1
  :: Sec                -- ^ local static secret
  -> Pub                -- ^ local static public
  -> Pub                -- ^ remote static public (responder's)
  -> BS.ByteString      -- ^ 32 bytes entropy for ephemeral
  -> Either Error (BS.ByteString, HandshakeState)
initiator_act1 s_sec s_pub rs ent = do
  -- Generate ephemeral keypair
  (e_sec, e_pub) <- maybe (Left InvalidKey) Right (keypair ent)

  let !hs0 = init_handshake s_sec s_pub e_sec e_pub (Just rs) True
      !e_pub_bytes = serialize_pub e_pub
      !h1 = mix_hash (hs_h hs0) e_pub_bytes

  es <- maybe (Left InvalidKey) Right (ecdh e_sec rs)

  let !(ck1, temp_k1) = mix_key (hs_ck hs0) es

  c <- maybe (Left InvalidMAC) Right (encrypt_with_ad temp_k1 0 h1 BS.empty)

  let !h2 = mix_hash h1 c
      !msg = BS.singleton 0x00 <> e_pub_bytes <> c
      !hs1 = hs0 {
        hs_h      = h2
      , hs_ck     = ck1
      , hs_temp_k = temp_k1
      }

  Right (msg, hs1)

-- | Responder: process Act 1 and generate Act 2 message (50 bytes).
--
--   Takes local static key and 32 bytes of entropy for ephemeral key,
--   plus the 50-byte Act 1 message from initiator.
--
--   Returns the 50-byte Act 2 message and handshake state for finalize.
responder_act2
  :: Sec                -- ^ local static secret
  -> Pub                -- ^ local static public
  -> BS.ByteString      -- ^ 32 bytes entropy for ephemeral
  -> BS.ByteString      -- ^ Act 1 message (50 bytes)
  -> Either Error (BS.ByteString, HandshakeState)
responder_act2 s_sec s_pub ent act1 = do
  -- Validate length
  if BS.length act1 /= 50
    then Left InvalidLength
    else pure ()

  -- Parse Act 1: version || e.pub || c
  let !version = BS.index act1 0
      !re_bytes = BS.take 33 (BS.drop 1 act1)
      !c = BS.drop 34 act1

  -- Validate version
  if version /= 0x00
    then Left InvalidVersion
    else pure ()

  -- Parse remote ephemeral
  re <- maybe (Left InvalidPub) Right (parse_pub re_bytes)

  -- Generate our ephemeral keypair
  (e_sec, e_pub) <- maybe (Left InvalidKey) Right (keypair ent)

  -- Initialize state (responder doesn't know remote static yet)
  let !hs0 = init_handshake s_sec s_pub e_sec e_pub Nothing False

  -- h = SHA256(h || re)
  let !h1 = mix_hash (hs_h hs0) re_bytes

  -- es = ECDH(s.priv, re)
  es <- maybe (Left InvalidKey) Right (ecdh s_sec re)

  -- ck, temp_k1 = HKDF(ck, es)
  let !(ck1, temp_k1) = mix_key (hs_ck hs0) es

  -- Decrypt and verify MAC
  _ <- maybe (Left InvalidMAC) Right (decrypt_with_ad temp_k1 0 h1 c)

  -- h = SHA256(h || c)
  let !h2 = mix_hash h1 c

  -- Now generate Act 2
  -- h = SHA256(h || e.pub)
  let !e_pub_bytes = serialize_pub e_pub
      !h3 = mix_hash h2 e_pub_bytes

  -- ee = ECDH(e.priv, re)
  ee <- maybe (Left InvalidKey) Right (ecdh e_sec re)

  -- ck, temp_k2 = HKDF(ck, ee)
  let !(ck2, temp_k2) = mix_key ck1 ee

  -- c2 = encrypt(temp_k2, 0, h, "")
  c2 <- maybe (Left InvalidMAC) Right (encrypt_with_ad temp_k2 0 h3 BS.empty)

  -- h = SHA256(h || c2)
  let !h4 = mix_hash h3 c2

  -- Build message: version || e.pub || c2
  let !msg = BS.singleton 0x00 <> e_pub_bytes <> c2

  let !hs1 = hs0 {
        hs_h      = h4
      , hs_ck     = ck2
      , hs_temp_k = temp_k2
      , hs_re     = Just re
      }

  Right (msg, hs1)

-- | Initiator: process Act 2 and generate Act 3 (66 bytes), completing
--   the handshake.
--
--   Returns the 66-byte Act 3 message and the session result.
initiator_act3
  :: HandshakeState     -- ^ state after Act 1
  -> BS.ByteString      -- ^ Act 2 message (50 bytes)
  -> Either Error (BS.ByteString, HandshakeResult)
initiator_act3 hs act2 = do
  -- Validate length
  if BS.length act2 /= 50
    then Left InvalidLength
    else pure ()

  -- Parse Act 2: version || e.pub || c
  let !version = BS.index act2 0
      !re_bytes = BS.take 33 (BS.drop 1 act2)
      !c = BS.drop 34 act2

  -- Validate version
  if version /= 0x00
    then Left InvalidVersion
    else pure ()

  -- Parse remote ephemeral
  re <- maybe (Left InvalidPub) Right (parse_pub re_bytes)

  -- h = SHA256(h || re)
  let !h1 = mix_hash (hs_h hs) re_bytes

  -- ee = ECDH(e.priv, re)
  ee <- maybe (Left InvalidKey) Right (ecdh (hs_e_sec hs) re)

  -- ck, temp_k2 = HKDF(ck, ee)
  let !(ck1, temp_k2) = mix_key (hs_ck hs) ee

  -- Decrypt and verify MAC
  _ <- maybe (Left InvalidMAC) Right (decrypt_with_ad temp_k2 0 h1 c)

  -- h = SHA256(h || c)
  let !h2 = mix_hash h1 c

  -- Now generate Act 3
  -- c = encrypt(temp_k2, 1, h, s.pub)
  let !s_pub_bytes = serialize_pub (hs_s_pub hs)
  c3 <- maybe (Left InvalidMAC) Right (encrypt_with_ad temp_k2 1 h2 s_pub_bytes)

  -- h = SHA256(h || c)
  let !h3 = mix_hash h2 c3

  -- se = ECDH(s.priv, re)
  se <- maybe (Left InvalidKey) Right (ecdh (hs_s_sec hs) re)

  -- ck, temp_k3 = HKDF(ck, se)
  let !(ck2, temp_k3) = mix_key ck1 se

  -- t = encrypt(temp_k3, 0, h, "")
  t <- maybe (Left InvalidMAC) Right (encrypt_with_ad temp_k3 0 h3 BS.empty)

  -- Derive session keys: sk, rk = HKDF(ck, "")
  let !(sk, rk) = mix_key ck2 BS.empty

  -- Build message: version || c || t
  let !msg = BS.singleton 0x00 <> c3 <> t

  -- Build session (initiator: sk = send, rk = receive)
  let !session = Session {
        sess_sk  = sk
      , sess_sn  = 0
      , sess_sck = ck2
      , sess_rk  = rk
      , sess_rn  = 0
      , sess_rck = ck2
      }

  -- Get remote static from handshake state (we knew it from the start)
  rs <- maybe (Left InvalidPub) Right (hs_rs hs)

  let !result = HandshakeResult {
        hr_session   = session
      , hr_remote_pk = rs
      }

  Right (msg, result)

-- | Responder: process Act 3 (66 bytes) and complete the handshake.
--
--   Returns the session result with authenticated remote static pubkey.
responder_finalize
  :: HandshakeState     -- ^ state after Act 2
  -> BS.ByteString      -- ^ Act 3 message (66 bytes)
  -> Either Error HandshakeResult
responder_finalize hs act3 = do
  -- Validate length
  if BS.length act3 /= 66
    then Left InvalidLength
    else pure ()

  -- Parse Act 3: version || encrypted_static (49 bytes) || t (16 bytes)
  let !version = BS.index act3 0
      !c = BS.take 49 (BS.drop 1 act3)
      !t = BS.drop 50 act3

  -- Validate version
  if version /= 0x00
    then Left InvalidVersion
    else pure ()

  -- Decrypt static key: rs = decrypt(temp_k2, 1, h, c)
  rs_bytes <- maybe (Left InvalidMAC) Right
    (decrypt_with_ad (hs_temp_k hs) 1 (hs_h hs) c)

  -- Parse remote static
  rs <- maybe (Left InvalidPub) Right (parse_pub rs_bytes)

  -- h = SHA256(h || c)
  let !h1 = mix_hash (hs_h hs) c

  -- se = ECDH(e.priv, rs)
  se <- maybe (Left InvalidKey) Right (ecdh (hs_e_sec hs) rs)

  -- ck, temp_k3 = HKDF(ck, se)
  let !(ck1, temp_k3) = mix_key (hs_ck hs) se

  -- Decrypt and verify final MAC
  _ <- maybe (Left InvalidMAC) Right (decrypt_with_ad temp_k3 0 h1 t)

  -- Derive session keys: rk, sk = HKDF(ck, "")
  -- Note: responder swaps order (receives what initiator sends)
  let !(rk, sk) = mix_key ck1 BS.empty

  -- Build session (responder: sk = send, rk = receive)
  let !session = Session {
        sess_sk  = sk
      , sess_sn  = 0
      , sess_sck = ck1
      , sess_rk  = rk
      , sess_rn  = 0
      , sess_rck = ck1
      }

  let !result = HandshakeResult {
        hr_session   = session
      , hr_remote_pk = rs
      }

  Right result

-- message encryption --------------------------------------------------------

-- | Encrypt a message (max 65535 bytes).
--
--   Returns the encrypted packet and updated session.
--
--   Wire format: encrypted_length (2) || MAC (16) || encrypted_body || MAC (16)
encrypt_message
  :: Session
  -> BS.ByteString          -- ^ plaintext (max 65535 bytes)
  -> Either Error (BS.ByteString, Session)
encrypt_message sess pt = do
  -- Validate length
  let !len = BS.length pt
  if len > 65535
    then Left InvalidLength
    else pure ()

  -- Encrypt length (2-byte big-endian)
  let !len_bytes = encode_be16 (fi len)
  lc <- maybe (Left InvalidMAC) Right
    (encrypt_with_ad (sess_sk sess) (sess_sn sess) BS.empty len_bytes)

  -- Step nonce (possibly rotate)
  let !(sn1, sck1, sk1) = step_nonce (sess_sn sess) (sess_sck sess) (sess_sk sess)

  -- Encrypt body
  bc <- maybe (Left InvalidMAC) Right
    (encrypt_with_ad sk1 sn1 BS.empty pt)

  -- Step nonce again (possibly rotate)
  let !(sn2, sck2, sk2) = step_nonce sn1 sck1 sk1

  -- Build packet
  let !packet = lc <> bc

  -- Update session
  let !sess' = sess {
        sess_sk  = sk2
      , sess_sn  = sn2
      , sess_sck = sck2
      }

  Right (packet, sess')

-- | Decrypt a message.
--
--   Returns the plaintext and updated session.
decrypt_message
  :: Session
  -> BS.ByteString          -- ^ encrypted packet
  -> Either Error (BS.ByteString, Session)
decrypt_message sess packet = do
  -- Need at least length ciphertext (18 bytes) + body MAC (16 bytes)
  if BS.length packet < 34
    then Left InvalidLength
    else pure ()

  -- Split length ciphertext
  let !lc = BS.take 18 packet
      !rest = BS.drop 18 packet

  -- Decrypt length
  len_bytes <- maybe (Left InvalidMAC) Right
    (decrypt_with_ad (sess_rk sess) (sess_rn sess) BS.empty lc)

  len <- maybe (Left InvalidLength) Right (decode_be16 len_bytes)

  -- Step nonce (possibly rotate)
  let !(rn1, rck1, rk1) = step_nonce (sess_rn sess) (sess_rck sess) (sess_rk sess)

  -- Validate we have enough data for body
  let !body_len = fi len + 16
  if BS.length rest < body_len
    then Left InvalidLength
    else pure ()

  -- Split body ciphertext
  let !bc = BS.take body_len rest

  -- Decrypt body
  pt <- maybe (Left InvalidMAC) Right
    (decrypt_with_ad rk1 rn1 BS.empty bc)

  -- Step nonce again (possibly rotate)
  let !(rn2, rck2, rk2) = step_nonce rn1 rck1 rk1

  -- Update session
  let !sess' = sess {
        sess_rk  = rk2
      , sess_rn  = rn2
      , sess_rck = rck2
      }

  Right (pt, sess')

-- key rotation --------------------------------------------------------------

-- Key rotation occurs after nonce reaches 1000 (i.e., before using 1000)
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

-- utilities -----------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}
