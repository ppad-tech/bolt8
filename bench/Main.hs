{-# OPTIONS_GHC -fno-warn-incomplete-uni-patterns #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import Criterion.Main
import qualified Data.ByteString as BS
import qualified Lightning.Protocol.BOLT8.Internal as BOLT8

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
  , bench "serialize_pub" $
      nf BOLT8.serialize_pub r_s_pub
  ]
  where
    Just (_, r_s_pub) = BOLT8.keypair r_s_ent
    r_s_pub_bs = BOLT8.serialize_pub r_s_pub

handshake :: Benchmark
handshake = env setup $
  \ ~(i_s_sec, i_s_pub, r_s_sec, r_s_pub,
      msg1, i_hs, msg2, r_hs, msg3) ->
    bgroup "handshake" [
      bench "act1" $
        nf (BOLT8.act1 i_s_sec i_s_pub r_s_pub) i_e_ent
    , bench "act2" $
        nf (BOLT8.act2 r_s_sec r_s_pub r_e_ent) msg1
    , bench "act3" $
        nf (BOLT8.act3 i_hs) msg2
    , bench "finalize" $
        nf (BOLT8.finalize r_hs) msg3
    ]
  where
    setup = do
      let Just (!i_s_sec, !i_s_pub) =
            BOLT8.keypair i_s_ent
          Just (!r_s_sec, !r_s_pub) =
            BOLT8.keypair r_s_ent
          Right (!msg1, !i_hs) =
            BOLT8.act1 i_s_sec i_s_pub r_s_pub i_e_ent
          Right (!msg2, !r_hs) =
            BOLT8.act2 r_s_sec r_s_pub r_e_ent msg1
          Right (!msg3, _) = BOLT8.act3 i_hs msg2
      pure ( i_s_sec, i_s_pub, r_s_sec, r_s_pub
           , msg1, i_hs, msg2, r_hs, msg3 )

messages :: Benchmark
messages = env setup $
  \ ~(i_sess, r_sess, ct_small, ct_large) ->
    bgroup "messages" [
      bench "encrypt (32B)" $
        nf (BOLT8.encrypt i_sess) small_msg
    , bench "encrypt (1KB)" $
        nf (BOLT8.encrypt i_sess) large_msg
    , bench "decrypt (32B)" $
        nf (BOLT8.decrypt r_sess) ct_small
    , bench "decrypt (1KB)" $
        nf (BOLT8.decrypt r_sess) ct_large
    ]
  where
    small_msg = BS.replicate 32 0x00
    large_msg = BS.replicate 1024 0x00
    setup = do
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
          Right (!ct_small, _) =
            BOLT8.encrypt i_sess small_msg
          Right (!ct_large, _) =
            BOLT8.encrypt i_sess large_msg
      pure (i_sess, r_sess, ct_small, ct_large)
