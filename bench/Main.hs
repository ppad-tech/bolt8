module Main where

import Criterion.Main
import qualified Data.ByteString as BS
import Fixture
import qualified Lightning.Protocol.BOLT8 as BOLT8

main :: IO ()
main = do
  fx <- fixture
  defaultMain [
      keys fx
    , handshake fx
    , transport fx
    ]

keys :: Fixture -> Benchmark
keys fx = bgroup "keys" [
    bench "keypair" $ nf BOLT8.keypair i_s_ent
  , bench "parse_pub" $ nf BOLT8.parse_pub pub_bs
  , bench "serialize_pub" $ nf BOLT8.serialize_pub pub
  ]
  where
    pub = BOLT8.keypair_pub (fx_r fx)
    pub_bs = BOLT8.serialize_pub pub

handshake :: Fixture -> Benchmark
handshake fx = bgroup "handshake" [
    bench "act1" $
      nf (BOLT8.act1 (fx_i fx) (BOLT8.keypair_pub (fx_r fx))) i_e_ent
  , bench "act2" $ nf (BOLT8.act2 (fx_r fx) r_e_ent) (fx_msg1 fx)
  , bench "act3" $ nf (BOLT8.act3 (fx_i_hs fx)) (fx_msg2 fx)
  , bench "finalize" $ nf (BOLT8.finalize (fx_r_hs fx)) (fx_msg3 fx)
  ]

transport :: Fixture -> Benchmark
transport fx = bgroup "transport" [
    bench "encrypt (32B)" $ nf (BOLT8.encrypt (fx_snd fx)) msg_32
  , bench "encrypt (1KB)" $ nf (BOLT8.encrypt (fx_snd fx)) msg_1k
  , bench "encrypt (64KB)" $ nf (BOLT8.encrypt (fx_snd fx)) msg_64k
  , bench "encrypt (32B, rotating)" $
      nf (BOLT8.encrypt (fx_snd_rot fx)) msg_32
  , bench "decrypt (32B)" $ nf (BOLT8.decrypt (fx_rcv fx)) (fx_ct_32 fx)
  , bench "decrypt (1KB)" $ nf (BOLT8.decrypt (fx_rcv fx)) (fx_ct_1k fx)
  , bench "decrypt (64KB)" $ nf (BOLT8.decrypt (fx_rcv fx)) (fx_ct_64k fx)
  , bench "decrypt_header" $
      nf (BOLT8.decrypt_header (fx_rcv fx)) (BS.take 18 (fx_ct_1k fx))
  , bench "decrypt_body (1KB)" $
      nf (BOLT8.decrypt_body (fx_pend_1k fx)) (BS.drop 18 (fx_ct_1k fx))
  ]
