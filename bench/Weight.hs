{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import qualified Data.ByteString as BS
import qualified Lightning.Protocol.BOLT8 as BOLT8
import Weigh

instance NFData BOLT8.Pub where
  rnf p = rnf (BOLT8.serialize_pub p)

instance NFData BOLT8.Sec
instance NFData BOLT8.Error
instance NFData BOLT8.Session
instance NFData BOLT8.HandshakeState
instance NFData BOLT8.HandshakeResult

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
        func "serialize_pub" BOLT8.serialize_pub r_s_pub

handshake :: Weigh ()
handshake =
  let Just (!i_s_sec, !i_s_pub) = BOLT8.keypair i_s_ent
      Just (!r_s_sec, !r_s_pub) = BOLT8.keypair r_s_ent
      Right (!act1, !i_hs) =
        BOLT8.initiator_act1 i_s_sec i_s_pub r_s_pub i_e_ent
      Right (!act2, !r_hs) =
        BOLT8.responder_act2 r_s_sec r_s_pub r_e_ent act1
      Right (!act3, _) = BOLT8.initiator_act3 i_hs act2
  in  wgroup "handshake" $ do
        func "initiator_act1"
          (BOLT8.initiator_act1 i_s_sec i_s_pub r_s_pub) i_e_ent
        func "responder_act2"
          (BOLT8.responder_act2 r_s_sec r_s_pub r_e_ent) act1
        func "initiator_act3" (BOLT8.initiator_act3 i_hs) act2
        func "responder_finalize" (BOLT8.responder_finalize r_hs) act3

messages :: Weigh ()
messages =
  let Just (!i_s_sec, !i_s_pub) = BOLT8.keypair i_s_ent
      Just (!r_s_sec, !r_s_pub) = BOLT8.keypair r_s_ent
      Right (act1, i_hs) =
        BOLT8.initiator_act1 i_s_sec i_s_pub r_s_pub i_e_ent
      Right (act2, r_hs) =
        BOLT8.responder_act2 r_s_sec r_s_pub r_e_ent act1
      Right (act3, i_result) = BOLT8.initiator_act3 i_hs act2
      Right r_result = BOLT8.responder_finalize r_hs act3
      !i_sess = BOLT8.hr_session i_result
      !r_sess = BOLT8.hr_session r_result
      !small_msg = BS.replicate 32 0x00
      !large_msg = BS.replicate 1024 0x00
      Right (!ct_small, _) = BOLT8.encrypt_message i_sess small_msg
      Right (!ct_large, _) = BOLT8.encrypt_message i_sess large_msg
  in  wgroup "messages" $ do
        func "encrypt (32B)" (BOLT8.encrypt_message i_sess) small_msg
        func "encrypt (1KB)" (BOLT8.encrypt_message i_sess) large_msg
        func "decrypt (32B)" (BOLT8.decrypt_message r_sess) ct_small
        func "decrypt (1KB)" (BOLT8.decrypt_message r_sess) ct_large
