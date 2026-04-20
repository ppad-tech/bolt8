{-# OPTIONS_HADDOCK prune #-}

-- |
-- Module: Lightning.Protocol.BOLT8
-- Copyright: (c) 2025 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Encrypted and authenticated transport for the Lightning
-- Network, per
-- [BOLT #8](https://github.com/lightning/bolts/blob/master/08-transport.md).
--
-- This module implements the
-- Noise_XK_secp256k1_ChaChaPoly_SHA256 handshake and
-- subsequent encrypted message transport.
--
-- = Handshake
--
-- A BOLT #8 handshake consists of three acts. The
-- /initiator/ knows the responder's static public key in
-- advance and initiates the connection:
--
-- @
-- (msg1, state) <- act1 i_sec i_pub r_pub entropy
-- -- send msg1 (50 bytes) to responder
-- -- receive msg2 (50 bytes) from responder
-- (msg3, result) <- act3 state msg2
-- -- send msg3 (66 bytes) to responder
-- let session = 'session' result
-- @
--
-- The /responder/ receives the connection and authenticates
-- the initiator:
--
-- @
-- -- receive msg1 (50 bytes) from initiator
-- (msg2, state) <- act2 r_sec r_pub entropy msg1
-- -- send msg2 (50 bytes) to initiator
-- -- receive msg3 (66 bytes) from initiator
-- result <- finalize state msg3
-- let session = 'session' result
-- @
--
-- = Message Transport
--
-- After a successful handshake, use 'encrypt' and 'decrypt'
-- to exchange messages. Each returns an updated 'Session'
-- that must be used for the next operation (keys rotate
-- every 1000 messages):
--
-- @
-- -- sender
-- (ciphertext, session') <- 'encrypt' session plaintext
--
-- -- receiver
-- (plaintext, session') <- 'decrypt' session ciphertext
-- @
--
-- = Message Framing
--
-- BOLT #8 runs over a byte stream, so callers often need to
-- deal with partial buffers. Use 'decrypt_frame' when you
-- have exactly one frame, or 'decrypt_frame_partial' to
-- handle incremental reads and return how many bytes are
-- still needed.
--
-- Maximum plaintext size is 65535 bytes.

module Lightning.Protocol.BOLT8 (
    -- * Keys
    Sec
  , Pub
  , keypair
  , parse_pub
  , serialize_pub

    -- * Newtypes
  , Key32
  , key32
  , unKey32
  , SessionNonce
  , unSessionNonce
  , MessagePayload
  , unMessagePayload
  , mkMessagePayload

    -- * Handshake roles
  , Initiator
  , Responder
  , HandshakeFor

    -- * Handshake (initiator)
  , act1
  , act3

    -- * Handshake (responder)
  , act2
  , finalize

    -- * Session
  , Session
  , HandshakeState
  , Handshake(..)
  , encrypt
  , decrypt
  , decrypt_frame
  , decrypt_frame_partial
  , FrameResult(..)

    -- * Errors
  , Error(..)
  ) where

import Lightning.Protocol.BOLT8.Internal
