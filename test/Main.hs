{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Lightning.Protocol.BOLT8 as BOLT8
import Test.Tasty
import Test.Tasty.HUnit

main :: IO ()
main = defaultMain $ testGroup "ppad-bolt8" [
    handshake_tests
  , message_tests
  , framing_tests
  , partial_framing_tests
  , negative_tests
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
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (act1_msg, _hs) -> act1_msg @?= expected_act1

test_act2 :: Assertion
test_act2 = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, _) -> do
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, _) -> msg2 @?= expected_act2

test_act3 :: Assertion
test_act3 = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) -> do
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, _) -> do
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, _) -> msg3 @?= expected_act3

test_full_handshake :: Assertion
test_full_handshake = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) -> do
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) -> do
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) -> do
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
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
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> fail $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> fail $ "act2 failed: " ++ show err
        Right (msg2, _) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> fail $ "act3 failed: " ++ show err
            Right (_, result) -> pure (BOLT8.session result)

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
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  case BOLT8.encrypt i_sess hello of
                    Left err -> assertFailure $ "encrypt failed: " ++ show err
                    Right (ct, _) ->
                      case BOLT8.decrypt r_sess ct of
                        Left err ->
                          assertFailure $ "decrypt failed: " ++ show err
                        Right (pt, _) -> pt @?= hello

-- framing tests -------------------------------------------------------------

framing_tests :: TestTree
framing_tests = testGroup "Packet Framing" [
    testCase "decrypt rejects trailing bytes" test_decrypt_trailing
  , testCase "decrypt_frame returns remainder" test_decrypt_frame_remainder
  , testCase "decrypt_frame handles multiple frames" test_decrypt_frame_multi
  ]

test_decrypt_trailing :: Assertion
test_decrypt_trailing = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  case BOLT8.encrypt i_sess hello of
                    Left err -> assertFailure $ "encrypt failed: " ++ show err
                    Right (ct, _) -> do
                      -- append trailing bytes
                      let ct_with_trailing = ct <> "extra"
                      case BOLT8.decrypt r_sess ct_with_trailing of
                        Left BOLT8.InvalidLength -> pure ()
                        Left err ->
                          assertFailure $ "expected InvalidLength, got: "
                            ++ show err
                        Right _ ->
                          assertFailure "decrypt should reject trailing bytes"

test_decrypt_frame_remainder :: Assertion
test_decrypt_frame_remainder = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  case BOLT8.encrypt i_sess hello of
                    Left err -> assertFailure $ "encrypt failed: " ++ show err
                    Right (ct, _) -> do
                      let trailing = "remainder"
                          ct_with_trailing = ct <> trailing
                      case BOLT8.decrypt_frame r_sess ct_with_trailing of
                        Left err ->
                          assertFailure $ "decrypt_frame failed: " ++ show err
                        Right (pt, remainder, _) -> do
                          pt @?= hello
                          remainder @?= trailing

test_decrypt_frame_multi :: Assertion
test_decrypt_frame_multi = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub

  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  -- encrypt two messages
                  case BOLT8.encrypt i_sess "first" of
                    Left err -> assertFailure $ "encrypt 1 failed: " ++ show err
                    Right (ct1, i_sess') ->
                      case BOLT8.encrypt i_sess' "second" of
                        Left err ->
                          assertFailure $ "encrypt 2 failed: " ++ show err
                        Right (ct2, _) -> do
                          -- concatenate frames
                          let buffer = ct1 <> ct2
                          -- decrypt first frame
                          case BOLT8.decrypt_frame r_sess buffer of
                            Left err ->
                              assertFailure $ "frame 1 failed: " ++ show err
                            Right (pt1, rest, r_sess') -> do
                              pt1 @?= "first"
                              -- decrypt second frame from remainder
                              case BOLT8.decrypt_frame r_sess' rest of
                                Left err ->
                                  assertFailure $ "frame 2 failed: " ++ show err
                                Right (pt2, rest2, _) -> do
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
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, _) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let r_sess = BOLT8.session r_result
                      short_buf = BS.replicate 10 0x00
                  case BOLT8.decrypt_frame_partial r_sess short_buf of
                    BOLT8.NeedMore n -> n @?= 8
                    BOLT8.FrameOk {} ->
                      assertFailure "expected NeedMore, got FrameOk"
                    BOLT8.FrameError err ->
                      assertFailure $ "expected NeedMore, got: " ++ show err

test_partial_body :: Assertion
test_partial_body = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  case BOLT8.encrypt i_sess hello of
                    Left err -> assertFailure $ "encrypt failed: " ++ show err
                    Right (ct, _) -> do
                      -- take only length header (18 bytes) + 5 bytes of body
                      let partial = BS.take 23 ct
                      case BOLT8.decrypt_frame_partial r_sess partial of
                        BOLT8.NeedMore n -> do
                          -- "hello" = 5 bytes, so body = 5 + 16 = 21
                          -- we have 5 bytes of body, need 16 more
                          n @?= 16
                        BOLT8.FrameOk {} ->
                          assertFailure "expected NeedMore, got FrameOk"
                        BOLT8.FrameError err ->
                          assertFailure $ "expected NeedMore, got: " ++ show err

test_partial_full_frame :: Assertion
test_partial_full_frame = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, i_result) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let i_sess = BOLT8.session i_result
                      r_sess = BOLT8.session r_result
                  case BOLT8.encrypt i_sess hello of
                    Left err -> assertFailure $ "encrypt failed: " ++ show err
                    Right (ct, _) -> do
                      let trailing = "extra"
                          buf = ct <> trailing
                      case BOLT8.decrypt_frame_partial r_sess buf of
                        BOLT8.FrameOk pt remainder _ -> do
                          pt @?= hello
                          remainder @?= trailing
                        BOLT8.NeedMore n ->
                          assertFailure $ "expected FrameOk, got NeedMore "
                            ++ show n
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
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, _) -> do
      let bad_msg1 = BS.cons 0x01 (BS.drop 1 msg1)
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv bad_msg1 of
        Left BOLT8.InvalidVersion -> pure ()
        Left err -> assertFailure $ "expected InvalidVersion, got: " ++ show err
        Right _ -> assertFailure "expected rejection, got success"

test_act2_wrong_length :: Assertion
test_act2_wrong_length = do
  let Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      short_msg = BS.replicate 49 0x00
  case BOLT8.act2 r_s_sec r_s_pub responder_e_priv short_msg of
    Left BOLT8.InvalidLength -> pure ()
    Left err -> assertFailure $ "expected InvalidLength, got: " ++ show err
    Right _ -> assertFailure "expected rejection, got success"

test_act3_invalid_mac :: Assertion
test_act3_invalid_mac = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, _) -> do
          let bad_msg2 = flip_byte 40 msg2
          case BOLT8.act3 i_hs bad_msg2 of
            Left BOLT8.InvalidMAC -> pure ()
            Left err ->
              assertFailure $ "expected InvalidMAC, got: " ++ show err
            Right _ -> assertFailure "expected rejection, got success"

test_finalize_invalid_mac :: Assertion
test_finalize_invalid_mac = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, _) -> do
              let bad_msg3 = flip_byte 20 msg3
              case BOLT8.finalize r_hs bad_msg3 of
                Left BOLT8.InvalidMAC -> pure ()
                Left err ->
                  assertFailure $ "expected InvalidMAC, got: " ++ show err
                Right _ -> assertFailure "expected rejection, got success"

test_decrypt_short_packet :: Assertion
test_decrypt_short_packet = do
  let Just (i_s_sec, i_s_pub) = BOLT8.keypair initiator_s_priv
      Just (r_s_sec, r_s_pub) = BOLT8.keypair responder_s_priv
      Just rs = BOLT8.parse_pub responder_s_pub
  case BOLT8.act1 i_s_sec i_s_pub rs initiator_e_priv of
    Left err -> assertFailure $ "act1 failed: " ++ show err
    Right (msg1, i_hs) ->
      case BOLT8.act2 r_s_sec r_s_pub responder_e_priv msg1 of
        Left err -> assertFailure $ "act2 failed: " ++ show err
        Right (msg2, r_hs) ->
          case BOLT8.act3 i_hs msg2 of
            Left err -> assertFailure $ "act3 failed: " ++ show err
            Right (msg3, _) ->
              case BOLT8.finalize r_hs msg3 of
                Left err -> assertFailure $ "finalize failed: " ++ show err
                Right r_result -> do
                  let r_sess = BOLT8.session r_result
                      short_packet = BS.replicate 17 0x00
                  case BOLT8.decrypt r_sess short_packet of
                    Left BOLT8.InvalidLength -> pure ()
                    Left err ->
                      assertFailure $ "expected InvalidLength, got: " ++ show err
                    Right _ -> assertFailure "expected rejection, got success"

-- flip one byte in a bytestring at given index
flip_byte :: Int -> BS.ByteString -> BS.ByteString
flip_byte i bs
  | i < 0 || i >= BS.length bs = error "flip_byte: index out of bounds"
  | otherwise =
      let (pre, post) = BS.splitAt i bs
          b = BS.index post 0
      in pre <> BS.cons (b `xor` 0xff) (BS.drop 1 post)

-- utilities -----------------------------------------------------------------

hex :: BS.ByteString -> BS.ByteString
hex bs = case B16.decode bs of
  Nothing -> error "invalid hex"
  Just r -> r
