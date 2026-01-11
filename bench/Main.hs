{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Data.ByteString as BS
import qualified Lightning.Protocol.BOLT8 as BOLT8

instance NFData BOLT8.Pub where
  rnf p = rnf (BOLT8.serialize_pub p)

instance NFData BOLT8.Sec
instance NFData BOLT8.Error
instance NFData BOLT8.Session
instance NFData BOLT8.HandshakeState
instance NFData BOLT8.HandshakeResult

main :: IO ()
main = defaultMain [
    keys
  , handshake
  , messages
  ]

-- test keys (from BOLT #8 spec)
i_s_ent, i_e_ent, r_s_ent, r_e_ent :: BS.ByteString
i_s_ent = BS.replicate 32 0x11
i_e_ent = BS.replicate 32 0x12
r_s_ent = BS.replicate 32 0x21
r_e_ent = BS.replicate 32 0x22

keys :: Benchmark
keys = bgroup "keys" [
    bench "keypair" $ nf BOLT8.keypair i_s_ent
  , bench "parse_pub" $ nf BOLT8.parse_pub r_s_pub_bs
  , bench "serialize_pub" $ nf BOLT8.serialize_pub r_s_pub
  ]
  where
    Just (_, r_s_pub) = BOLT8.keypair r_s_ent
    r_s_pub_bs = BOLT8.serialize_pub r_s_pub

handshake :: Benchmark
handshake = env setup $ \ ~(i_s_sec, i_s_pub, r_s_sec, r_s_pub, act1, i_hs,
                            act2, r_hs, act3) ->
    bgroup "handshake" [
      bench "initiator_act1" $
        nf (BOLT8.initiator_act1 i_s_sec i_s_pub r_s_pub) i_e_ent
    , bench "responder_act2" $
        nf (BOLT8.responder_act2 r_s_sec r_s_pub r_e_ent) act1
    , bench "initiator_act3" $
        nf (BOLT8.initiator_act3 i_hs) act2
    , bench "responder_finalize" $
        nf (BOLT8.responder_finalize r_hs) act3
    ]
  where
    setup = do
      let Just (!i_s_sec, !i_s_pub) = BOLT8.keypair i_s_ent
          Just (!r_s_sec, !r_s_pub) = BOLT8.keypair r_s_ent
          Right (!act1, !i_hs) =
            BOLT8.initiator_act1 i_s_sec i_s_pub r_s_pub i_e_ent
          Right (!act2, !r_hs) =
            BOLT8.responder_act2 r_s_sec r_s_pub r_e_ent act1
          Right (!act3, _) = BOLT8.initiator_act3 i_hs act2
      pure (i_s_sec, i_s_pub, r_s_sec, r_s_pub, act1, i_hs, act2, r_hs, act3)

messages :: Benchmark
messages = env setup $ \ ~(i_sess, r_sess, ct_small, ct_large) ->
    bgroup "messages" [
      bench "encrypt (32B)" $
        nf (BOLT8.encrypt_message i_sess) small_msg
    , bench "encrypt (1KB)" $
        nf (BOLT8.encrypt_message i_sess) large_msg
    , bench "decrypt (32B)" $
        nf (BOLT8.decrypt_message r_sess) ct_small
    , bench "decrypt (1KB)" $
        nf (BOLT8.decrypt_message r_sess) ct_large
    ]
  where
    small_msg = BS.replicate 32 0x00
    large_msg = BS.replicate 1024 0x00
    setup = do
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
          Right (!ct_small, _) = BOLT8.encrypt_message i_sess small_msg
          Right (!ct_large, _) = BOLT8.encrypt_message i_sess large_msg
      pure (i_sess, r_sess, ct_small, ct_large)
