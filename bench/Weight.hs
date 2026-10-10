module Main where

import qualified Data.ByteString as BS
import Fixture
import qualified Lightning.Protocol.BOLT8 as BOLT8
import Weigh

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = do
  fx <- fixture
  mainWith $ do
    keys fx
    handshake fx
    transport fx

keys :: Fixture -> Weigh ()
keys fx = wgroup "keys" $ do
    func "keypair" BOLT8.keypair i_s_ent
    func "parse_pub" BOLT8.parse_pub pub_bs
    func "serialize_pub" BOLT8.serialize_pub pub
  where
    pub = BOLT8.keypair_pub (fx_r fx)
    pub_bs = BOLT8.serialize_pub pub

handshake :: Fixture -> Weigh ()
handshake fx = wgroup "handshake" $ do
  func "act1"
    (BOLT8.act1 (fx_i fx) (BOLT8.keypair_pub (fx_r fx))) i_e_ent
  func "act2" (BOLT8.act2 (fx_r fx) r_e_ent) (fx_msg1 fx)
  func "act3" (BOLT8.act3 (fx_i_hs fx)) (fx_msg2 fx)
  func "finalize" (BOLT8.finalize (fx_r_hs fx)) (fx_msg3 fx)

transport :: Fixture -> Weigh ()
transport fx = wgroup "transport" $ do
  func "encrypt (32B)" (BOLT8.encrypt (fx_snd fx)) msg_32
  func "encrypt (1KB)" (BOLT8.encrypt (fx_snd fx)) msg_1k
  func "encrypt (64KB)" (BOLT8.encrypt (fx_snd fx)) msg_64k
  func "encrypt (32B, rotating)" (BOLT8.encrypt (fx_snd_rot fx)) msg_32
  func "decrypt (32B)" (BOLT8.decrypt (fx_rcv fx)) (fx_ct_32 fx)
  func "decrypt (1KB)" (BOLT8.decrypt (fx_rcv fx)) (fx_ct_1k fx)
  func "decrypt (64KB)" (BOLT8.decrypt (fx_rcv fx)) (fx_ct_64k fx)
  func "decrypt_header"
    (BOLT8.decrypt_header (fx_rcv fx)) (BS.take 18 (fx_ct_1k fx))
  func "decrypt_body (1KB)"
    (BOLT8.decrypt_body (fx_pend_1k fx)) (BS.drop 18 (fx_ct_1k fx))
