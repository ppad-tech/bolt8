module Fixture (
    i_s_ent
  , i_e_ent
  , r_s_ent
  , r_e_ent
  , msg_32
  , msg_1k
  , msg_64k
  , Fixture(..)
  , fixture
  ) where

import qualified Data.ByteString as BS
import qualified Lightning.Protocol.BOLT8 as BOLT8

-- key material from BOLT #8 Appendix A
i_s_ent, i_e_ent, r_s_ent, r_e_ent :: BS.ByteString
i_s_ent = BS.replicate 32 0x11
i_e_ent = BS.replicate 32 0x12
r_s_ent = BS.replicate 32 0x21
r_e_ent = BS.replicate 32 0x22

data Fixture = Fixture {
    fx_i       :: !BOLT8.Keypair
  , fx_r       :: !BOLT8.Keypair
  , fx_msg1    :: !BS.ByteString
  , fx_i_hs    :: !BOLT8.Initiator
  , fx_msg2    :: !BS.ByteString
  , fx_r_hs    :: !BOLT8.Responder
  , fx_msg3    :: !BS.ByteString
  , fx_snd     :: !BOLT8.Sender
  , fx_snd_rot :: !BOLT8.Sender   -- its next encrypt rotates the key
  , fx_rcv     :: !BOLT8.Receiver
  , fx_ct_32   :: !BS.ByteString
  , fx_ct_1k   :: !BS.ByteString
  , fx_ct_64k  :: !BS.ByteString
  , fx_pend_1k :: !BOLT8.Pending  -- awaiting the body of fx_ct_1k
  }

fixture :: IO Fixture
fixture = do
  i <- orFail "keypair" (maybe (Left ()) Right (BOLT8.keypair i_s_ent))
  r <- orFail "keypair" (maybe (Left ()) Right (BOLT8.keypair r_s_ent))
  (msg1, i_hs) <- orFail "act1" (BOLT8.act1 i (BOLT8.keypair_pub r) i_e_ent)
  (msg2, r_hs) <- orFail "act2" (BOLT8.act2 r r_e_ent msg1)
  (msg3, i_res) <- orFail "act3" (BOLT8.act3 i_hs msg2)
  r_res <- orFail "finalize" (BOLT8.finalize r_hs msg3)
  let snd0 = BOLT8.handshake_sender i_res
      rcv0 = BOLT8.handshake_receiver r_res
  snd_rot <- advance (499 :: Int) snd0
  (ct_32, _) <- orFail "encrypt" (BOLT8.encrypt snd0 msg_32)
  (ct_1k, _) <- orFail "encrypt" (BOLT8.encrypt snd0 msg_1k)
  (ct_64k, _) <- orFail "encrypt" (BOLT8.encrypt snd0 msg_64k)
  (_, pend_1k) <- orFail "header"
    (BOLT8.decrypt_header rcv0 (BS.take 18 ct_1k))
  pure Fixture {
      fx_i = i, fx_r = r
    , fx_msg1 = msg1, fx_i_hs = i_hs
    , fx_msg2 = msg2, fx_r_hs = r_hs
    , fx_msg3 = msg3
    , fx_snd = snd0, fx_snd_rot = snd_rot
    , fx_rcv = rcv0
    , fx_ct_32 = ct_32, fx_ct_1k = ct_1k, fx_ct_64k = ct_64k
    , fx_pend_1k = pend_1k
    }
  where
    orFail :: Show e => String -> Either e a -> IO a
    orFail msg = either (\e -> fail (msg <> ": " <> show e)) pure
    advance 0 s = pure s
    advance n s = do
      (_, s') <- orFail "encrypt" (BOLT8.encrypt s msg_32)
      advance (n - 1) s'

msg_32, msg_1k, msg_64k :: BS.ByteString
msg_32 = BS.replicate 32 0x00
msg_1k = BS.replicate 1024 0x00
msg_64k = BS.replicate 65535 0x00
