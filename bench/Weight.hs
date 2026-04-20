{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import qualified Data.ByteString as BS
import qualified Lightning.Protocol.BOLT8.Internal as BOLT8
import Weigh

instance NFData BOLT8.Pub where
  rnf p = rnf (BOLT8.serialize_pub p)

instance NFData BOLT8.Sec
instance NFData BOLT8.Error
instance NFData BOLT8.Key32
instance NFData BOLT8.SessionNonce
instance NFData BOLT8.Session
instance NFData BOLT8.HandshakeState
instance NFData BOLT8.Handshake
instance NFData (BOLT8.HandshakeFor a) where
  rnf (BOLT8.HandshakeFor s) = rnf s

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = mainWith $ do
  keys
  handshake
  messages

-- test keys (from BOLT #8 spec)
i_s_ent, i_e_ent, r_s_ent, r_e_ent :: BS.ByteString
i_s_ent = BS.replicate 32 0x11
i_e_ent = BS.replicate 32 0x12
r_s_ent = BS.replicate 32 0x21
r_e_ent = BS.replicate 32 0x22

keys :: Weigh ()
keys =
  let Just (_, !r_s_pub) = BOLT8.keypair r_s_ent
      !r_s_pub_bs = BOLT8.serialize_pub r_s_pub
  in  wgroup "keys" $ do
        func "keypair" BOLT8.keypair i_s_ent
        func "parse_pub" BOLT8.parse_pub r_s_pub_bs
        func "serialize_pub"
          BOLT8.serialize_pub r_s_pub

handshake :: Weigh ()
handshake =
  let Just (!i_s_sec, !i_s_pub) =
        BOLT8.keypair i_s_ent
      Just (!r_s_sec, !r_s_pub) =
        BOLT8.keypair r_s_ent
      Right (!msg1, !i_hs) =
        BOLT8.act1 i_s_sec i_s_pub r_s_pub i_e_ent
      Right (!msg2, !r_hs) =
        BOLT8.act2 r_s_sec r_s_pub r_e_ent msg1
      Right (!msg3, _) = BOLT8.act3 i_hs msg2
  in  wgroup "handshake" $ do
        func "act1"
          (BOLT8.act1 i_s_sec i_s_pub r_s_pub) i_e_ent
        func "act2"
          (BOLT8.act2 r_s_sec r_s_pub r_e_ent) msg1
        func "act3" (BOLT8.act3 i_hs) msg2
        func "finalize" (BOLT8.finalize r_hs) msg3

messages :: Weigh ()
messages =
  let Just (!i_s_sec, !i_s_pub) =
        BOLT8.keypair i_s_ent
      Just (!r_s_sec, !r_s_pub) =
        BOLT8.keypair r_s_ent
      Right (msg1, i_hs) =
        BOLT8.act1 i_s_sec i_s_pub r_s_pub i_e_ent
      Right (msg2, r_hs) =
        BOLT8.act2 r_s_sec r_s_pub r_e_ent msg1
      Right (msg3, i_result) =
        BOLT8.act3 i_hs msg2
      Right r_result =
        BOLT8.finalize r_hs msg3
      !i_sess = BOLT8.session i_result
      !r_sess = BOLT8.session r_result
      !small_msg = BS.replicate 32 0x00
      !large_msg = BS.replicate 1024 0x00
      Right (!ct_small, _) =
        BOLT8.encrypt i_sess small_msg
      Right (!ct_large, _) =
        BOLT8.encrypt i_sess large_msg
  in  wgroup "messages" $ do
        func "encrypt (32B)"
          (BOLT8.encrypt i_sess) small_msg
        func "encrypt (1KB)"
          (BOLT8.encrypt i_sess) large_msg
        func "decrypt (32B)"
          (BOLT8.decrypt r_sess) ct_small
        func "decrypt (1KB)"
          (BOLT8.decrypt r_sess) ct_large
