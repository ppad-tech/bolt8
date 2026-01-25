{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Lightning.Protocol.BOLT8 as BOLT8
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck (Gen, Property, choose, forAll, testProperty,
                              vectorOf)

-- test helpers ----------------------------------------------------------------

-- | Extract a Just value or fail the test.
expectJust :: String -> Maybe a -> IO a
expectJust msg = \case
  Nothing -> assertFailure msg >> error "unreachable"
  Just a  -> pure a

-- | Extract a Right value or fail the test.
expectRight :: Show e => String -> Either e a -> IO a
expectRight msg = \case
  Left e  -> assertFailure (msg ++ ": " ++ show e) >> error "unreachable"
  Right a -> pure a

main :: IO ()
main = defaultMain $ testGroup "ppad-bolt8" [
    handshake_tests
  , message_tests
  , framing_tests
  , partial_framing_tests
  , negative_tests
  , property_tests
  ]

-- test vectors from BOLT #8 specification -----------------------------------

-- initiator static private key
initiator_s_priv :: BS.ByteString
initiator_s_priv = hex
  "1111111111111111111111111111111111111111111111111111111111111111"

-- initiator ephemeral private key
initiator_e_priv :: BS.ByteString
initiator_e_priv = hex
  "1212121212121212121212121212121212121212121212121212121212121212"

-- responder static private key
responder_s_priv :: BS.ByteString
responder_s_priv = hex
  "2121212121212121212121212121212121212121212121212121212121212121"

-- responder static public key (known to initiator)
responder_s_pub :: BS.ByteString
responder_s_pub = hex
  "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"

-- responder ephemeral private key
responder_e_priv :: BS.ByteString
responder_e_priv = hex
  "2222222222222222222222222222222222222222222222222222222222222222"

-- expected act 1 message
expected_act1 :: BS.ByteString
expected_act1 = hex
  "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
  \0df6086551151f58b8afe6c195782c6a"

-- expected act 2 message
expected_act2 :: BS.ByteString
expected_act2 = hex
  "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
  \6e2470b93aac583c9ef6eafca3f730ae"

-- expected act 3 message
expected_act3 :: BS.ByteString
expected_act3 = hex
  "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
  \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"

-- handshake tests -----------------------------------------------------------

handshake_tests :: TestTree
handshake_tests = testGroup "Handshake" [
    testCase "act1 matches spec vector" test_act1
  , testCase "act2 matches spec vector" test_act2
  , testCase "act3 matches spec vector" test_act3
  , testCase "full handshake round-trip" test_full_handshake
  ]

test_act1 :: Assertion
test_act1 = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (act1_msg, _) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                        initiator_e_priv)
  act1_msg @?= expected_act1

test_act2 :: Assertion
test_act2 = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, _) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                    initiator_e_priv)
  (msg2, _) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                    msg1)
  msg2 @?= expected_act2

test_act3 :: Assertion
test_act3 = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, _) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                    msg1)
  (msg3, _) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  msg3 @?= expected_act3

test_full_handshake :: Assertion
test_full_handshake = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  BOLT8.remote_static i_result @?= r_s_pub
  BOLT8.remote_static r_result @?= i_s_pub

-- message encryption tests --------------------------------------------------

message_tests :: TestTree
message_tests = testGroup "Message Encryption" [
    testCase "message 0 matches spec" test_message_0
  , testCase "message 1 matches spec" test_message_1
  , testCase "message 500 matches spec" test_message_500
  , testCase "message 501 matches spec" test_message_501
  , testCase "message 1000 matches spec" test_message_1000
  , testCase "message 1001 matches spec" test_message_1001
  , testCase "decrypt round-trip" test_decrypt_roundtrip
  ]

-- "hello" = 0x68656c6c6f
hello :: BS.ByteString
hello = "hello"

-- expected encrypted messages
expected_msg_0 :: BS.ByteString
expected_msg_0 = hex
  "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d\
  \2f214cf9ea1d95"

expected_msg_1 :: BS.ByteString
expected_msg_1 = hex
  "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d\
  \7ad833b1a256a1"

expected_msg_500 :: BS.ByteString
expected_msg_500 = hex
  "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f4\
  \8364f7a4c68bf8"

expected_msg_501 :: BS.ByteString
expected_msg_501 = hex
  "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c\
  \104b56b60e45bd"

expected_msg_1000 :: BS.ByteString
expected_msg_1000 = hex
  "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c5\
  \2b76b29b740f09"

expected_msg_1001 :: BS.ByteString
expected_msg_1001 = hex
  "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338\
  \b1a16cf4ef2d36"

-- helper to get initiator session after handshake
get_initiator_session :: IO BOLT8.Session
get_initiator_session = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, _) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                    msg1)
  (_, result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  pure (BOLT8.session result)

-- encrypt N messages, return Nth ciphertext
encrypt_n :: Int -> BOLT8.Session -> IO BS.ByteString
encrypt_n n sess0 = go 0 sess0
  where
    go i sess
      | i == n = case BOLT8.encrypt sess hello of
          Left err -> fail $ "encrypt failed at " ++ show i ++ ": " ++ show err
          Right (ct, _) -> pure ct
      | otherwise = case BOLT8.encrypt sess hello of
          Left err -> fail $ "encrypt failed at " ++ show i ++ ": " ++ show err
          Right (_, sess') -> go (i + 1) sess'

test_message_0 :: Assertion
test_message_0 = do
  sess <- get_initiator_session
  ct <- encrypt_n 0 sess
  ct @?= expected_msg_0

test_message_1 :: Assertion
test_message_1 = do
  sess <- get_initiator_session
  ct <- encrypt_n 1 sess
  ct @?= expected_msg_1

test_message_500 :: Assertion
test_message_500 = do
  sess <- get_initiator_session
  ct <- encrypt_n 500 sess
  ct @?= expected_msg_500

test_message_501 :: Assertion
test_message_501 = do
  sess <- get_initiator_session
  ct <- encrypt_n 501 sess
  ct @?= expected_msg_501

test_message_1000 :: Assertion
test_message_1000 = do
  sess <- get_initiator_session
  ct <- encrypt_n 1000 sess
  ct @?= expected_msg_1000

test_message_1001 :: Assertion
test_message_1001 = do
  sess <- get_initiator_session
  ct <- encrypt_n 1001 sess
  ct @?= expected_msg_1001

test_decrypt_roundtrip :: Assertion
test_decrypt_roundtrip = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  (ct, _) <- expectRight "encrypt" (BOLT8.encrypt i_sess hello)
  (pt, _) <- expectRight "decrypt" (BOLT8.decrypt r_sess ct)
  pt @?= hello

-- framing tests -------------------------------------------------------------

framing_tests :: TestTree
framing_tests = testGroup "Packet Framing" [
    testCase "decrypt rejects trailing bytes" test_decrypt_trailing
  , testCase "decrypt_frame returns remainder" test_decrypt_frame_remainder
  , testCase "decrypt_frame handles multiple frames" test_decrypt_frame_multi
  ]

test_decrypt_trailing :: Assertion
test_decrypt_trailing = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  (ct, _) <- expectRight "encrypt" (BOLT8.encrypt i_sess hello)
  -- append trailing bytes
  let ct_with_trailing = ct <> "extra"
  case BOLT8.decrypt r_sess ct_with_trailing of
    Left BOLT8.InvalidLength -> pure ()
    Left err -> assertFailure $ "expected InvalidLength, got: " ++ show err
    Right _ -> assertFailure "decrypt should reject trailing bytes"

test_decrypt_frame_remainder :: Assertion
test_decrypt_frame_remainder = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  (ct, _) <- expectRight "encrypt" (BOLT8.encrypt i_sess hello)
  let trailing = "remainder"
      ct_with_trailing = ct <> trailing
  (pt, remainder, _) <- expectRight "decrypt_frame"
                          (BOLT8.decrypt_frame r_sess ct_with_trailing)
  pt @?= hello
  remainder @?= trailing

test_decrypt_frame_multi :: Assertion
test_decrypt_frame_multi = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  -- encrypt two messages
  (ct1, i_sess') <- expectRight "encrypt 1" (BOLT8.encrypt i_sess "first")
  (ct2, _) <- expectRight "encrypt 2" (BOLT8.encrypt i_sess' "second")
  -- concatenate frames
  let buffer = ct1 <> ct2
  -- decrypt first frame
  (pt1, rest, r_sess') <- expectRight "frame 1"
                            (BOLT8.decrypt_frame r_sess buffer)
  pt1 @?= "first"
  -- decrypt second frame from remainder
  (pt2, rest2, _) <- expectRight "frame 2" (BOLT8.decrypt_frame r_sess' rest)
  pt2 @?= "second"
  rest2 @?= BS.empty

-- partial framing tests -----------------------------------------------------

partial_framing_tests :: TestTree
partial_framing_tests = testGroup "Partial Framing" [
    testCase "short buffer returns NeedMore" test_partial_short_buffer
  , testCase "partial body returns NeedMore" test_partial_body
  , testCase "full frame returns FrameOk" test_partial_full_frame
  ]

test_partial_short_buffer :: Assertion
test_partial_short_buffer = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, _) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let r_sess = BOLT8.session r_result
      short_buf = BS.replicate 10 0x00
  case BOLT8.decrypt_frame_partial r_sess short_buf of
    BOLT8.NeedMore n -> n @?= 8
    BOLT8.FrameOk {} -> assertFailure "expected NeedMore, got FrameOk"
    BOLT8.FrameError err ->
      assertFailure $ "expected NeedMore, got: " ++ show err

test_partial_body :: Assertion
test_partial_body = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  (ct, _) <- expectRight "encrypt" (BOLT8.encrypt i_sess hello)
  -- take only length header (18 bytes) + 5 bytes of body
  let partial = BS.take 23 ct
  case BOLT8.decrypt_frame_partial r_sess partial of
    BOLT8.NeedMore n -> do
      -- "hello" = 5 bytes, so body = 5 + 16 = 21
      -- we have 5 bytes of body, need 16 more
      n @?= 16
    BOLT8.FrameOk {} -> assertFailure "expected NeedMore, got FrameOk"
    BOLT8.FrameError err ->
      assertFailure $ "expected NeedMore, got: " ++ show err

test_partial_full_frame :: Assertion
test_partial_full_frame = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, i_result) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let i_sess = BOLT8.session i_result
      r_sess = BOLT8.session r_result
  (ct, _) <- expectRight "encrypt" (BOLT8.encrypt i_sess hello)
  let trailing = "extra"
      buf = ct <> trailing
  case BOLT8.decrypt_frame_partial r_sess buf of
    BOLT8.FrameOk pt remainder _ -> do
      pt @?= hello
      remainder @?= trailing
    BOLT8.NeedMore n ->
      assertFailure $ "expected FrameOk, got NeedMore " ++ show n
    BOLT8.FrameError err ->
      assertFailure $ "expected FrameOk, got: " ++ show err

-- negative tests ------------------------------------------------------------

negative_tests :: TestTree
negative_tests = testGroup "Negative Tests" [
    testCase "act2 rejects wrong version" test_act2_wrong_version
  , testCase "act2 rejects wrong length" test_act2_wrong_length
  , testCase "act3 rejects invalid MAC" test_act3_invalid_mac
  , testCase "finalize rejects invalid MAC" test_finalize_invalid_mac
  , testCase "decrypt rejects short packet" test_decrypt_short_packet
  ]

test_act2_wrong_version :: Assertion
test_act2_wrong_version = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, _) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv)
  let bad_msg1 = BS.cons 0x01 (BS.drop 1 msg1)
  case BOLT8.act2 r_s_sec r_s_pub responder_e_priv bad_msg1 of
    Left BOLT8.InvalidVersion -> pure ()
    Left err -> assertFailure $ "expected InvalidVersion, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

test_act2_wrong_length :: Assertion
test_act2_wrong_length = do
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  let short_msg = BS.replicate 49 0x00
  case BOLT8.act2 r_s_sec r_s_pub responder_e_priv short_msg of
    Left BOLT8.InvalidLength -> pure ()
    Left err -> assertFailure $ "expected InvalidLength, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

test_act3_invalid_mac :: Assertion
test_act3_invalid_mac = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, _) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                    msg1)
  bad_msg2 <- flip_byte 40 msg2
  case BOLT8.act3 i_hs bad_msg2 of
    Left BOLT8.InvalidMAC -> pure ()
    Left err -> assertFailure $ "expected InvalidMAC, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

test_finalize_invalid_mac :: Assertion
test_finalize_invalid_mac = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, _) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  bad_msg3 <- flip_byte 20 msg3
  case BOLT8.finalize r_hs bad_msg3 of
    Left BOLT8.InvalidMAC -> pure ()
    Left err -> assertFailure $ "expected InvalidMAC, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

test_decrypt_short_packet :: Assertion
test_decrypt_short_packet = do
  (i_s_sec, i_s_pub) <- expectJust "initiator keypair"
                          (BOLT8.keypair initiator_s_priv)
  (r_s_sec, r_s_pub) <- expectJust "responder keypair"
                          (BOLT8.keypair responder_s_priv)
  rs <- expectJust "responder pub" (BOLT8.parse_pub responder_s_pub)
  (msg1, i_hs) <- expectRight "act1" (BOLT8.act1 i_s_sec i_s_pub rs
                                       initiator_e_priv)
  (msg2, r_hs) <- expectRight "act2" (BOLT8.act2 r_s_sec r_s_pub responder_e_priv
                                       msg1)
  (msg3, _) <- expectRight "act3" (BOLT8.act3 i_hs msg2)
  r_result <- expectRight "finalize" (BOLT8.finalize r_hs msg3)
  let r_sess = BOLT8.session r_result
      short_packet = BS.replicate 17 0x00
  case BOLT8.decrypt r_sess short_packet of
    Left BOLT8.InvalidLength -> pure ()
    Left err -> assertFailure $ "expected InvalidLength, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

-- flip one byte in a bytestring at given index
flip_byte :: Int -> BS.ByteString -> IO BS.ByteString
flip_byte i bs
  | i < 0 || i >= BS.length bs =
      assertFailure "flip_byte: index out of bounds" >> pure bs
  | otherwise =
      let (pre, post) = BS.splitAt i bs
          b = BS.index post 0
      in pure (pre <> BS.cons (b `xor` 0xff) (BS.drop 1 post))

-- utilities -----------------------------------------------------------------

-- Safe hex decode for test vectors (only called at top level with known-good
-- literals). This uses error since it's for compile-time constants, not runtime
-- input; wrapping in IO would break the test vector declarations.
hex :: BS.ByteString -> BS.ByteString
hex bs = case B16.decode bs of
  Nothing -> error "hex: invalid test vector literal"
  Just r  -> r

-- property tests --------------------------------------------------------------

property_tests :: TestTree
property_tests = testGroup "Properties" [
    testProperty "handshake round-trip" prop_handshake_roundtrip
  , testProperty "encrypt/decrypt round-trip" prop_encrypt_decrypt_roundtrip
  , testProperty "decrypt_frame consumes one frame" prop_frame_consumes_one
  , testProperty "decrypt_frame_partial NeedMore on short"
      prop_partial_needmore_short
  ]

-- generators ------------------------------------------------------------------

-- | Generate 32 bytes of entropy that yields a valid keypair.
genValidEntropy :: Gen BS.ByteString
genValidEntropy = do
  bytes <- BS.pack <$> vectorOf 32 (choose (0, 255))
  case BOLT8.keypair bytes of
    Just _  -> pure bytes
    Nothing -> genValidEntropy

-- | Generate a payload of 0..256 bytes.
genPayload :: Gen BS.ByteString
genPayload = do
  len <- choose (0, 256)
  BS.pack <$> vectorOf len (choose (0, 255))

-- | Perform a full handshake with given static key entropy.
-- Uses fixed ephemeral keys for determinism.
doHandshake
  :: BS.ByteString
  -> BS.ByteString
  -> Maybe (BOLT8.Session, BOLT8.Session)
doHandshake i_entropy r_entropy = do
  (i_s_sec, i_s_pub) <- BOLT8.keypair i_entropy
  (r_s_sec, r_s_pub) <- BOLT8.keypair r_entropy
  let i_e = BS.replicate 32 0x12
      r_e = BS.replicate 32 0x22
  (msg1, i_hs) <- either (const Nothing) Just $
    BOLT8.act1 i_s_sec i_s_pub r_s_pub i_e
  (msg2, r_hs) <- either (const Nothing) Just $
    BOLT8.act2 r_s_sec r_s_pub r_e msg1
  (msg3, i_res) <- either (const Nothing) Just $
    BOLT8.act3 i_hs msg2
  r_res <- either (const Nothing) Just $
    BOLT8.finalize r_hs msg3
  pure (BOLT8.session i_res, BOLT8.session r_res)

-- properties ------------------------------------------------------------------

-- | Handshake succeeds for valid keys and sessions are consistent.
prop_handshake_roundtrip :: Property
prop_handshake_roundtrip = forAll genValidEntropy $ \i_ent ->
  forAll genValidEntropy $ \r_ent ->
    case doHandshake i_ent r_ent of
      Nothing -> False
      Just _  -> True

-- | Encrypt then decrypt yields original payload.
prop_encrypt_decrypt_roundtrip :: Property
prop_encrypt_decrypt_roundtrip = forAll genPayload $ \payload ->
  case doHandshake initiator_s_priv responder_s_priv of
    Nothing -> False
    Just (i_sess, r_sess) ->
      case BOLT8.encrypt i_sess payload of
        Left _ -> False
        Right (ct, _) ->
          case BOLT8.decrypt r_sess ct of
            Left _ -> False
            Right (pt, _) -> pt == payload

-- | decrypt_frame consumes exactly one frame and returns remainder.
prop_frame_consumes_one :: Property
prop_frame_consumes_one = forAll genPayload $ \p1 ->
  forAll genPayload $ \p2 ->
    case doHandshake initiator_s_priv responder_s_priv of
      Nothing -> False
      Just (i_sess, r_sess) ->
        case BOLT8.encrypt i_sess p1 of
          Left _ -> False
          Right (ct1, i_sess') ->
            case BOLT8.encrypt i_sess' p2 of
              Left _ -> False
              Right (ct2, _) ->
                let buf = ct1 <> ct2
                in case BOLT8.decrypt_frame r_sess buf of
                  Left _ -> False
                  Right (pt1, rest, r_sess') ->
                    pt1 == p1 &&
                    case BOLT8.decrypt_frame r_sess' rest of
                      Left _ -> False
                      Right (pt2, rest2, _) ->
                        pt2 == p2 && BS.null rest2

-- | decrypt_frame_partial returns NeedMore when buffer < 18 bytes.
prop_partial_needmore_short :: Property
prop_partial_needmore_short = forAll (choose (0, 17)) $ \len ->
  case doHandshake initiator_s_priv responder_s_priv of
    Nothing -> False
    Just (_, r_sess) ->
      let buf = BS.replicate len 0x00
      in case BOLT8.decrypt_frame_partial r_sess buf of
        BOLT8.NeedMore n -> n == 18 - len
        _                -> False
