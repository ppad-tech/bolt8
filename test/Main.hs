{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Crypto.AEAD.ChaCha20Poly1305 as AEAD
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.KDF.HMAC as HKDF
import Data.Bits (shiftR, xor)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (isJust, isNothing)
import Data.Word (Word64)
import qualified Lightning.Protocol.BOLT8 as BOLT8
import Test.Tasty
import Test.Tasty.HUnit
import qualified Test.Tasty.QuickCheck as Q

main :: IO ()
main = defaultMain $ testGroup "ppad-bolt8" [
    key_tests
  , handshake_tests
  , handshake_failure_tests
  , message_tests
  , transport_tests
  , transport_failure_tests
  , property_tests
  ]

-- helpers --------------------------------------------------------------------

expect_just :: String -> Maybe a -> IO a
expect_just msg = maybe (assertFailure msg) pure

expect_right :: Show e => String -> Either e a -> IO a
expect_right msg = either (\e -> assertFailure (msg <> ": " <> show e)) pure

-- assert failure with a specific error
expect_error :: String -> BOLT8.Error -> Either BOLT8.Error a -> Assertion
expect_error msg want r = case r of
  Left got -> assertEqual msg want got
  Right _  -> assertFailure (msg <> ": expected " <> show want)

-- decode a hex literal, failing the test if it is malformed
unhex :: BS.ByteString -> IO BS.ByteString
unhex h = expect_just ("invalid hex: " <> show h) (B16.decode h)

-- total lookup
at :: Int -> [a] -> Maybe a
at i xs = case drop i xs of
  (x : _) | i >= 0 -> Just x
  _                -> Nothing

-- flip all bits of the byte at the given index
flip_byte :: Int -> BS.ByteString -> IO BS.ByteString
flip_byte i bs
  | i < 0 || i >= BS.length bs =
      assertFailure ("flip_byte: index out of bounds: " <> show i)
  | otherwise =
      let (pre, post) = BS.splitAt i bs
      in  pure (pre <> BS.map (xor 0xff) (BS.take 1 post) <> BS.drop 1 post)

-- payload for the m'th message of a test stream
payload :: Int -> BS.ByteString
payload m = BS.replicate (m `mod` 7) (fromIntegral m)

-- Appendix A key material ----------------------------------------------------

ls_i_sec, e_i_sec, ls_r_sec, e_r_sec :: BS.ByteString
ls_i_sec = BS.replicate 32 0x11
e_i_sec  = BS.replicate 32 0x12
ls_r_sec = BS.replicate 32 0x21
e_r_sec  = BS.replicate 32 0x22

ls_i_pub, ls_r_pub, e_i_pub, e_r_pub :: BS.ByteString
ls_i_pub =
  "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
ls_r_pub =
  "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7"
e_i_pub =
  "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7"
e_r_pub =
  "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27"

act1_msg, act2_msg, act3_msg :: BS.ByteString
act1_msg =
  "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
  \0df6086551151f58b8afe6c195782c6a"
act2_msg =
  "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
  \6e2470b93aac583c9ef6eafca3f730ae"
act3_msg =
  "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
  \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"

-- final chaining key, and the initiator's sending and receiving keys
-- (the responder's are swapped)
final_ck, final_sk, final_rk :: BS.ByteString
final_ck =
  "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01"
final_sk =
  "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9"
final_rk =
  "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442"

spec_keypairs :: IO (BOLT8.Keypair, BOLT8.Keypair)
spec_keypairs = do
  i <- expect_just "initiator keypair" (BOLT8.keypair ls_i_sec)
  r <- expect_just "responder keypair" (BOLT8.keypair ls_r_sec)
  pure (i, r)

-- the Appendix A handshake, as (initiator, responder) results
spec_handshake :: Either BOLT8.Error (BOLT8.Handshake, BOLT8.Handshake)
spec_handshake = do
  i <- maybe (Left BOLT8.InvalidEntropy) Right (BOLT8.keypair ls_i_sec)
  r <- maybe (Left BOLT8.InvalidEntropy) Right (BOLT8.keypair ls_r_sec)
  handshake i r e_i_sec e_r_sec

spec_results :: IO (BOLT8.Handshake, BOLT8.Handshake)
spec_results = expect_right "spec handshake" spec_handshake

handshake
  :: BOLT8.Keypair
  -> BOLT8.Keypair
  -> BS.ByteString
  -> BS.ByteString
  -> Either BOLT8.Error (BOLT8.Handshake, BOLT8.Handshake)
handshake i r i_e r_e = do
  (msg1, i_hs) <- BOLT8.act1 i (BOLT8.keypair_pub r) i_e
  (msg2, r_hs) <- BOLT8.act2 r r_e msg1
  (msg3, i_res) <- BOLT8.act3 i_hs msg2
  r_res <- BOLT8.finalize r_hs msg3
  pure (i_res, r_res)

-- reference transport --------------------------------------------------------

-- BOLT #8 framing and rotation built directly on ppad-aead and
-- ppad-hkdf, as an independent check of the library's key schedule.

ref_nonce :: Word64 -> BS.ByteString
ref_nonce n = BS.replicate 4 0 <>
  BS.pack [fromIntegral (n `shiftR` (8 * j)) | j <- [0 .. 7]]

ref_frame :: BS.ByteString -> Word64 -> BS.ByteString -> IO BS.ByteString
ref_frame k n m = do
  let len = BS.length m
      l = BS.pack [fromIntegral (len `shiftR` 8), fromIntegral len]
  (lc, lt) <- expect_right "aead" (AEAD.encrypt mempty k (ref_nonce n) l)
  (c, t) <- expect_right "aead" (AEAD.encrypt mempty k (ref_nonce (n + 1)) m)
  pure (lc <> lt <> c <> t)

-- (ck', k') = HKDF(ck, k)
ref_rotate
  :: BS.ByteString -> BS.ByteString -> IO (BS.ByteString, BS.ByteString)
ref_rotate ck k = do
  out <- expect_just "hkdf" (HKDF.derive hmac ck mempty 64 k)
  pure (BS.splitAt 32 out)
  where
    hmac a b = case SHA256.hmac a b of SHA256.MAC mac -> mac

-- frames carrying 'payload' 0 .. count - 1, sent under key k and
-- chaining key ck
ref_stream :: BS.ByteString -> BS.ByteString -> Int -> IO [BS.ByteString]
ref_stream = go 0 0
  where
    go m n ck k count
      | m == count = pure []
      | n >= 1000 = do
          (ck', k') <- ref_rotate ck k
          go m 0 ck' k' count
      | otherwise = do
          f <- ref_frame k n (payload m)
          fs <- go (m + 1) (n + 2) ck k count
          pure (f : fs)

-- assert that a Sender encrypts under key k with chaining key ck,
-- across two rotations
check_sender :: BS.ByteString -> BS.ByteString -> BOLT8.Sender -> Assertion
check_sender ck k s0 = do
  ref <- ref_stream ck k 1002
  let go _ _ [] = pure ()
      go m s (f : fs) = do
        (ct, s') <- expect_right "encrypt" (BOLT8.encrypt s (payload m))
        assertEqual ("frame " <> show m) f ct
        go (m + 1) s' fs
  go (0 :: Int) s0 ref

-- assert that a Receiver decrypts under key k with chaining key ck,
-- across two rotations
check_receiver
  :: BS.ByteString -> BS.ByteString -> BOLT8.Receiver -> Assertion
check_receiver ck k r0 = do
  ref <- ref_stream ck k 1002
  let go _ _ [] = pure ()
      go m r (f : fs) = do
        (pt, r') <- expect_right ("decrypt " <> show m) (BOLT8.decrypt r f)
        assertEqual ("message " <> show m) (payload m) pt
        go (m + 1) r' fs
  go (0 :: Int) r0 ref

-- send 'payload' 0 .. count - 1 from a Sender to a Receiver
round_trip :: Int -> BOLT8.Sender -> BOLT8.Receiver -> Assertion
round_trip count = go 0
  where
    go m s r
      | m == count = pure ()
      | otherwise = do
          (ct, s') <- expect_right "encrypt" (BOLT8.encrypt s (payload m))
          (pt, r') <- expect_right ("decrypt " <> show m) (BOLT8.decrypt r ct)
          assertEqual ("message " <> show m) (payload m) pt
          go (m + 1) s' r'

-- keys -----------------------------------------------------------------------

-- 32-byte strings (and one short one) that are not valid secret keys
invalid_secrets :: IO [(String, BS.ByteString)]
invalid_secrets = do
  n <- unhex
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
  pure [
      ("zero", BS.replicate 32 0)
    , ("order", n)
    , ("2^256 - 1", BS.replicate 32 0xff)
    , ("31 bytes", BS.replicate 31 0x12)
    ]

-- 33-byte compressed encodings that are not curve points
invalid_points :: IO [(String, BS.ByteString)]
invalid_points = do
  -- x = p + 1 is congruent to 1, which is on the curve, but not < p
  p_1 <- unhex
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30"
  pure [
      ("x = 0, no square root", BS.cons 0x02 (BS.replicate 32 0))
    , ("x = 5, no square root", BS.cons 0x03 (BS.replicate 31 0 <> "\x05"))
    , ("x = p + 1", BS.cons 0x02 p_1)
    ]

-- replace the 33-byte key in a 50-byte act one or act two message
with_key :: BS.ByteString -> BS.ByteString -> BS.ByteString
with_key pt msg = BS.take 1 msg <> pt <> BS.drop 34 msg

key_tests :: TestTree
key_tests = testGroup "keys" [
    testCase "keypair derives the spec static keys" $ do
      (i, r) <- spec_keypairs
      want_i <- unhex ls_i_pub
      want_r <- unhex ls_r_pub
      BOLT8.serialize_pub (BOLT8.keypair_pub i) @?= want_i
      BOLT8.serialize_pub (BOLT8.keypair_pub r) @?= want_r
  , testCase "keypair rejects invalid secrets" $ do
      n <- unhex
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
      n_1 <- unhex
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
      assertBool "31 bytes" (isNothing (BOLT8.keypair (BS.replicate 31 1)))
      assertBool "33 bytes" (isNothing (BOLT8.keypair (BS.replicate 33 1)))
      assertBool "zero" (isNothing (BOLT8.keypair (BS.replicate 32 0)))
      assertBool "order" (isNothing (BOLT8.keypair n))
      assertBool "2^256 - 1" (isNothing (BOLT8.keypair (BS.replicate 32 0xff)))
      assertBool "order - 1" (isJust (BOLT8.keypair n_1))
  , testCase "parse_pub round-trips compressed keys" $ do
      bs <- unhex ls_r_pub
      pub <- expect_just "parse_pub" (BOLT8.parse_pub bs)
      BOLT8.serialize_pub pub @?= bs
  , testCase "parse_pub rejects points off the curve" $ do
      bad <- invalid_points
      mapM_ (\(name, pt) ->
               assertBool name (isNothing (BOLT8.parse_pub pt))) bad
  , testCase "parse_pub rejects other encodings" $ do
      -- the generator, uncompressed and x-only
      g_full <- unhex
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
        \483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
      g_x <- unhex
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      bs <- unhex ls_r_pub
      assertBool "uncompressed" (isNothing (BOLT8.parse_pub g_full))
      assertBool "x-only" (isNothing (BOLT8.parse_pub g_x))
      assertBool "0x04 prefix"
        (isNothing (BOLT8.parse_pub (BS.cons 0x04 (BS.drop 1 bs))))
      assertBool "34 bytes" (isNothing (BOLT8.parse_pub (bs <> "\x00")))
  ]

-- handshake ------------------------------------------------------------------

handshake_tests :: TestTree
handshake_tests = testGroup "handshake" [
    testCase "act one matches spec" $ do
      (i, _) <- spec_keypairs
      rs <- unhex ls_r_pub >>= expect_just "rs" . BOLT8.parse_pub
      (msg1, _) <- expect_right "act1" (BOLT8.act1 i rs e_i_sec)
      want <- unhex act1_msg
      e <- unhex e_i_pub
      msg1 @?= want
      BS.take 33 (BS.drop 1 msg1) @?= e
  , testCase "act two matches spec" $ do
      (_, r) <- spec_keypairs
      msg1 <- unhex act1_msg
      (msg2, _) <- expect_right "act2" (BOLT8.act2 r e_r_sec msg1)
      want <- unhex act2_msg
      e <- unhex e_r_pub
      msg2 @?= want
      BS.take 33 (BS.drop 1 msg2) @?= e
  , testCase "act three matches spec" $ do
      (i, r) <- spec_keypairs
      (_, i_hs) <- expect_right "act1"
        (BOLT8.act1 i (BOLT8.keypair_pub r) e_i_sec)
      msg2 <- unhex act2_msg
      (msg3, _) <- expect_right "act3" (BOLT8.act3 i_hs msg2)
      want <- unhex act3_msg
      msg3 @?= want
  , testCase "finalize accepts spec act three" $ do
      (_, r) <- spec_keypairs
      msg1 <- unhex act1_msg
      msg3 <- unhex act3_msg
      (_, r_hs) <- expect_right "act2" (BOLT8.act2 r e_r_sec msg1)
      r_res <- expect_right "finalize" (BOLT8.finalize r_hs msg3)
      want <- unhex ls_i_pub
      BOLT8.serialize_pub (BOLT8.handshake_remote_static r_res) @?= want
  , testCase "act1 rejects invalid entropy" $ do
      (i, r) <- spec_keypairs
      let rs = BOLT8.keypair_pub r
      bad <- invalid_secrets
      mapM_ (\(name, e) -> expect_error name BOLT8.InvalidEntropy
                             (BOLT8.act1 i rs e)) bad
  , testCase "act2 rejects invalid entropy" $ do
      (_, r) <- spec_keypairs
      msg1 <- unhex act1_msg
      bad <- invalid_secrets
      mapM_ (\(name, e) -> expect_error name BOLT8.InvalidEntropy
                             (BOLT8.act2 r e msg1)) bad
  , testCase "act2 rejects an ephemeral key off the curve" $ do
      (_, r) <- spec_keypairs
      msg1 <- unhex act1_msg
      bad <- invalid_points
      mapM_ (\(name, pt) -> expect_error name BOLT8.InvalidPub
                              (BOLT8.act2 r e_r_sec (with_key pt msg1))) bad
  , testCase "act3 rejects an ephemeral key off the curve" $ do
      (i, r) <- spec_keypairs
      (_, i_hs) <- expect_right "act1"
        (BOLT8.act1 i (BOLT8.keypair_pub r) e_i_sec)
      msg2 <- unhex act2_msg
      bad <- invalid_points
      mapM_ (\(name, pt) -> expect_error name BOLT8.InvalidPub
                              (BOLT8.act3 i_hs (with_key pt msg2))) bad
  , testCase "acts reject oversized input" $ do
      (i, r) <- spec_keypairs
      msg1 <- unhex act1_msg
      msg2 <- unhex act2_msg
      msg3 <- unhex act3_msg
      (_, i_hs) <- expect_right "act1"
        (BOLT8.act1 i (BOLT8.keypair_pub r) e_i_sec)
      (_, r_hs) <- expect_right "act2" (BOLT8.act2 r e_r_sec msg1)
      expect_error "act2" BOLT8.InvalidLength
        (BOLT8.act2 r e_r_sec (msg1 <> "\x00"))
      expect_error "act3" BOLT8.InvalidLength
        (BOLT8.act3 i_hs (msg2 <> "\x00"))
      expect_error "finalize" BOLT8.InvalidLength
        (BOLT8.finalize r_hs (msg3 <> "\x00"))
  ]

-- Appendix A failure vectors -------------------------------------------------

data Failure = Failure String BS.ByteString BOLT8.Error

handshake_failure_tests :: TestTree
handshake_failure_tests = testGroup "Appendix A failure vectors" [
    testGroup "initiator, act two" (fmap initiator_failure act2_failures)
  , testGroup "responder, act one" (fmap act1_failure act1_failures)
  , testGroup "responder, act three" (fmap act3_failure act3_failures)
  ]

initiator_failure :: Failure -> TestTree
initiator_failure (Failure name input want) = testCase name $ do
  (i, _) <- spec_keypairs
  rs <- unhex ls_r_pub >>= expect_just "rs" . BOLT8.parse_pub
  (msg1, i_hs) <- expect_right "act1" (BOLT8.act1 i rs e_i_sec)
  unhex act1_msg >>= (msg1 @?=)
  msg2 <- unhex input
  expect_error name want (BOLT8.act3 i_hs msg2)

act1_failure :: Failure -> TestTree
act1_failure (Failure name input want) = testCase name $ do
  (_, r) <- spec_keypairs
  msg1 <- unhex input
  expect_error name want (BOLT8.act2 r e_r_sec msg1)

act3_failure :: Failure -> TestTree
act3_failure (Failure name input want) = testCase name $ do
  (_, r) <- spec_keypairs
  msg1 <- unhex act1_msg
  (msg2, r_hs) <- expect_right "act2" (BOLT8.act2 r e_r_sec msg1)
  unhex act2_msg >>= (msg2 @?=)
  msg3 <- unhex input
  expect_error name want (BOLT8.finalize r_hs msg3)

act2_failures :: [Failure]
act2_failures = [
    Failure "short read"
      "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
      \6e2470b93aac583c9ef6eafca3f730"
      BOLT8.InvalidLength
  , Failure "bad version"
      "0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
      \6e2470b93aac583c9ef6eafca3f730ae"
      BOLT8.InvalidVersion
  , Failure "bad key serialization"
      "0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
      \6e2470b93aac583c9ef6eafca3f730ae"
      BOLT8.InvalidPub
  , Failure "bad MAC"
      "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27\
      \6e2470b93aac583c9ef6eafca3f730af"
      BOLT8.InvalidMAC
  ]

act1_failures :: [Failure]
act1_failures = [
    Failure "short read"
      "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
      \0df6086551151f58b8afe6c195782c"
      BOLT8.InvalidLength
  , Failure "bad version"
      "01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
      \0df6086551151f58b8afe6c195782c6a"
      BOLT8.InvalidVersion
  , Failure "bad key serialization"
      "00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
      \0df6086551151f58b8afe6c195782c6a"
      BOLT8.InvalidPub
  , Failure "bad MAC"
      "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7\
      \0df6086551151f58b8afe6c195782c6b"
      BOLT8.InvalidMAC
  ]

act3_failures :: [Failure]
act3_failures = [
    Failure "bad version"
      "01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
      \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
      BOLT8.InvalidVersion
  , Failure "short read"
      "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
      \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139"
      BOLT8.InvalidLength
  , Failure "bad MAC for ciphertext"
      "00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
      \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba"
      BOLT8.InvalidMAC
  , Failure "bad rs"
      "00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
      \36ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c"
      BOLT8.InvalidPub
  , Failure "bad MAC"
      "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355\
      \361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb"
      BOLT8.InvalidMAC
  ]

-- message encryption ---------------------------------------------------------

-- Appendix A message test: "hello" sent 1001 times by the initiator
spec_messages :: [(Int, BS.ByteString)]
spec_messages = [
    (0,    "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbc\
           \f25d2f214cf9ea1d95")
  , (1,    "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d\
           \0f0d7ad833b1a256a1")
  , (500,  "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb2\
           \20f48364f7a4c68bf8")
  , (501,  "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60\
           \ca2c104b56b60e45bd")
  , (1000, "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c\
           \05c52b76b29b740f09")
  , (1001, "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e26\
           \8338b1a16cf4ef2d36")
  ]

-- the initiator's first n frames, each carrying "hello"
hello_stream :: Int -> IO [BS.ByteString]
hello_stream count = do
  (i_res, _) <- spec_results
  let go m s
        | m == count = pure []
        | otherwise = do
            (ct, s') <- expect_right "encrypt" (BOLT8.encrypt s "hello")
            (ct :) <$> go (m + 1) s'
  go (0 :: Int) (BOLT8.handshake_sender i_res)

message_tests :: TestTree
message_tests = testGroup "messages" [
    testGroup "spec vectors" (fmap spec_message spec_messages)
  , testCase "responder decrypts the spec stream" $ do
      (_, r_res) <- spec_results
      frames <- hello_stream 1002
      let go _ _ [] = pure ()
          go m r (f : fs) = do
            (pt, r') <- expect_right ("decrypt " <> show m) (BOLT8.decrypt r f)
            assertEqual ("message " <> show m) "hello" pt
            go (m + 1) r' fs
      go (0 :: Int) (BOLT8.handshake_receiver r_res) frames
  , testCase "reference key rotation matches spec" $ do
      ck <- unhex final_ck
      sk <- unhex final_sk
      ck1 <- unhex
        "cc2c6e467efc8067720c2d09c139d1f77731893aad1defa14f9bf3c48d3f1d31"
      k1 <- unhex
        "3fbdc101abd1132ca3a0ae34a669d8d9ba69a587e0bb4ddd59524541cf4813d8"
      ck2 <- unhex
        "728366ed68565dc17cf6dd97330a859a6a56e87e2beef3bd828a4c4a54d8df06"
      k2 <- unhex
        "9e0477f9850dca41e42db0e4d154e3a098e5a000d995e421849fcd5df27882bd"
      ref_rotate ck sk >>= (@?= (ck1, k1))
      ref_rotate ck1 k1 >>= (@?= (ck2, k2))
  , testCase "initiator sends under sk and ck" $ do
      (i_res, _) <- spec_results
      ck <- unhex final_ck
      sk <- unhex final_sk
      check_sender ck sk (BOLT8.handshake_sender i_res)
  , testCase "initiator receives under rk and ck" $ do
      (i_res, _) <- spec_results
      ck <- unhex final_ck
      rk <- unhex final_rk
      check_receiver ck rk (BOLT8.handshake_receiver i_res)
  , testCase "responder sends under rk and ck" $ do
      (_, r_res) <- spec_results
      ck <- unhex final_ck
      rk <- unhex final_rk
      check_sender ck rk (BOLT8.handshake_sender r_res)
  , testCase "responder receives under sk and ck" $ do
      (_, r_res) <- spec_results
      ck <- unhex final_ck
      sk <- unhex final_sk
      check_receiver ck sk (BOLT8.handshake_receiver r_res)
  , testCase "initiator to responder across rotations" $ do
      (i_res, r_res) <- spec_results
      round_trip 1600
        (BOLT8.handshake_sender i_res) (BOLT8.handshake_receiver r_res)
  , testCase "responder to initiator across rotations" $ do
      (i_res, r_res) <- spec_results
      round_trip 1600
        (BOLT8.handshake_sender r_res) (BOLT8.handshake_receiver i_res)
  ]

spec_message :: (Int, BS.ByteString) -> TestTree
spec_message (m, h) = testCase ("message " <> show m) $ do
  frames <- hello_stream 1002
  got <- expect_just "frame" (at m frames)
  want <- unhex h
  got @?= want

-- transport ------------------------------------------------------------------

-- the spec handshake's transport states and the initiator's first two
-- frames, carrying "hello" and "world!"
transport_fixture
  :: IO (BOLT8.Sender, BOLT8.Receiver, BOLT8.Receiver, BS.ByteString,
         BS.ByteString)
transport_fixture = do
  (i_res, r_res) <- spec_results
  let i_snd = BOLT8.handshake_sender i_res
  (f0, i_snd') <- expect_right "encrypt" (BOLT8.encrypt i_snd "hello")
  (f1, _) <- expect_right "encrypt" (BOLT8.encrypt i_snd' "world!")
  pure ( i_snd, BOLT8.handshake_receiver i_res
       , BOLT8.handshake_receiver r_res, f0, f1 )

-- consume a buffer of frames via decrypt_header and decrypt_body
consume
  :: BOLT8.Receiver
  -> BS.ByteString
  -> Either BOLT8.Error [BS.ByteString]
consume r buf
  | BS.null buf = Right []
  | otherwise = do
      let (hdr, rest) = BS.splitAt 18 buf
      (n, p) <- BOLT8.decrypt_header r hdr
      let (body, rest') = BS.splitAt n rest
      (m, r') <- BOLT8.decrypt_body p body
      (m :) <$> consume r' rest'

transport_tests :: TestTree
transport_tests = testGroup "transport" [
    testCase "frame is message length plus 34 bytes" $ do
      (_, _, _, f0, f1) <- transport_fixture
      BS.length f0 @?= 5 + 34
      BS.length f1 @?= 6 + 34
  , testCase "decrypt_header reports the remaining length" $ do
      (_, _, r, f0, _) <- transport_fixture
      (n, _) <- expect_right "header" (BOLT8.decrypt_header r (BS.take 18 f0))
      n @?= 5 + 16
  , testCase "header and body decrypt consecutive frames" $ do
      (_, _, r, f0, f1) <- transport_fixture
      ms <- expect_right "consume" (consume r (f0 <> f1))
      ms @?= ["hello", "world!"]
  , testCase "decrypt agrees with header and body" $ do
      (_, _, r, f0, f1) <- transport_fixture
      (m0, r') <- expect_right "decrypt 0" (BOLT8.decrypt r f0)
      (m1, _) <- expect_right "decrypt 1" (BOLT8.decrypt r' f1)
      [m0, m1] @?= ["hello", "world!"]
  , testCase "empty message round-trips" $ do
      (s, _, r, _, _) <- transport_fixture
      (f, _) <- expect_right "encrypt" (BOLT8.encrypt s mempty)
      BS.length f @?= 34
      (m, _) <- expect_right "decrypt" (BOLT8.decrypt r f)
      m @?= mempty
  , testCase "65535-byte message round-trips" $ do
      (s, _, r, _, _) <- transport_fixture
      let big = BS.replicate 65535 0xab
      (f, _) <- expect_right "encrypt" (BOLT8.encrypt s big)
      BS.length f @?= 65569
      (n, _) <- expect_right "header" (BOLT8.decrypt_header r (BS.take 18 f))
      n @?= 65551
      (m, _) <- expect_right "decrypt" (BOLT8.decrypt r f)
      m @?= big
  , testCase "encrypt rejects a 65536-byte message" $ do
      (s, _, _, _, _) <- transport_fixture
      expect_error "encrypt" BOLT8.InvalidLength
        (BOLT8.encrypt s (BS.replicate 65536 0))
  ]

transport_failure_tests :: TestTree
transport_failure_tests = testGroup "transport failures" [
    testCase "bad length MAC" $ do
      (_, _, r, f0, _) <- transport_fixture
      for_bytes [2, 17] f0 $ \bad -> do
        expect_error "decrypt" BOLT8.InvalidMAC (BOLT8.decrypt r bad)
        expect_error "decrypt_header" BOLT8.InvalidMAC
          (BOLT8.decrypt_header r (BS.take 18 bad))
  , testCase "tampered length" $ do
      (_, _, r, f0, _) <- transport_fixture
      for_bytes [0, 1] f0 $ \bad -> do
        expect_error "decrypt" BOLT8.InvalidMAC (BOLT8.decrypt r bad)
        expect_error "decrypt_header" BOLT8.InvalidMAC
          (BOLT8.decrypt_header r (BS.take 18 bad))
  , testCase "bad body MAC" $ do
      (_, _, r, f0, _) <- transport_fixture
      for_bytes [18, 23, BS.length f0 - 1] f0 $ \bad -> do
        expect_error "decrypt" BOLT8.InvalidMAC (BOLT8.decrypt r bad)
        (n, p) <- expect_right "header"
          (BOLT8.decrypt_header r (BS.take 18 bad))
        expect_error "decrypt_body" BOLT8.InvalidMAC
          (BOLT8.decrypt_body p (BS.take n (BS.drop 18 bad)))
  , testCase "truncated frame" $ do
      (_, _, r, f0, _) <- transport_fixture
      let short = BS.take (BS.length f0 - 1) f0
      expect_error "decrypt" BOLT8.InvalidLength (BOLT8.decrypt r short)
      expect_error "decrypt, header only" BOLT8.InvalidLength
        (BOLT8.decrypt r (BS.take 18 f0))
      expect_error "decrypt, partial header" BOLT8.InvalidLength
        (BOLT8.decrypt r (BS.take 17 f0))
      expect_error "decrypt, empty" BOLT8.InvalidLength
        (BOLT8.decrypt r mempty)
      expect_error "decrypt_header" BOLT8.InvalidLength
        (BOLT8.decrypt_header r (BS.take 17 f0))
      (_, p) <- expect_right "header" (BOLT8.decrypt_header r (BS.take 18 f0))
      expect_error "decrypt_body" BOLT8.InvalidLength
        (BOLT8.decrypt_body p (BS.drop 18 short))
  , testCase "trailing bytes" $ do
      (_, _, r, f0, _) <- transport_fixture
      let long = f0 <> "\x00"
      expect_error "decrypt" BOLT8.InvalidLength (BOLT8.decrypt r long)
      expect_error "decrypt_header" BOLT8.InvalidLength
        (BOLT8.decrypt_header r (BS.take 19 f0))
      (_, p) <- expect_right "header" (BOLT8.decrypt_header r (BS.take 18 f0))
      expect_error "decrypt_body" BOLT8.InvalidLength
        (BOLT8.decrypt_body p (BS.drop 18 long))
  , testCase "replayed frame" $ do
      (_, _, r, f0, _) <- transport_fixture
      (_, r') <- expect_right "decrypt" (BOLT8.decrypt r f0)
      expect_error "replay" BOLT8.InvalidMAC (BOLT8.decrypt r' f0)
  , testCase "reordered frame" $ do
      (_, _, r, _, f1) <- transport_fixture
      expect_error "decrypt" BOLT8.InvalidMAC (BOLT8.decrypt r f1)
  , testCase "reflected frame" $ do
      (_, i_rcv, _, f0, _) <- transport_fixture
      expect_error "decrypt" BOLT8.InvalidMAC (BOLT8.decrypt i_rcv f0)
  ]
  where
    for_bytes is f act = mapM_ (\i -> flip_byte i f >>= act) is

-- properties -----------------------------------------------------------------

property_tests :: TestTree
property_tests = testGroup "properties" [
    Q.testProperty "handshake agrees on keys and statics" prop_handshake
  , Q.testProperty "messages up to 65535 bytes round-trip" prop_size
  , Q.testProperty "header and body recover a stream" prop_stream
  , Q.testProperty "parse_pub inverts serialize_pub" prop_pub
  ]

-- 32 bytes that form a valid secret key
gen_secret :: Q.Gen BS.ByteString
gen_secret = (BS.pack <$> Q.vectorOf 32 Q.arbitrary)
  `Q.suchThat` (isJust . BOLT8.keypair)

gen_bytes :: Int -> Q.Gen BS.ByteString
gen_bytes n = do
  len <- Q.choose (0, n)
  BS.pack <$> Q.vectorOf len Q.arbitrary

prop_handshake :: Q.Property
prop_handshake =
  Q.forAll gen_secret $ \i_s ->
  Q.forAll gen_secret $ \r_s ->
  Q.forAll gen_secret $ \i_e ->
  Q.forAll gen_secret $ \r_e ->
  Q.forAll (gen_bytes 256) $ \m ->
    case (BOLT8.keypair i_s, BOLT8.keypair r_s) of
      (Just i, Just r) -> check i r (handshake i r i_e r_e) m
      _ -> Q.counterexample "keypair" False
  where
    check _ _ (Left e) _ = Q.counterexample (show e) False
    check i r (Right (i_res, r_res)) m =
      let there = send (BOLT8.handshake_sender i_res)
                       (BOLT8.handshake_receiver r_res) m
          back  = send (BOLT8.handshake_sender r_res)
                       (BOLT8.handshake_receiver i_res) m
      in       BOLT8.handshake_remote_static i_res
                 Q.=== BOLT8.keypair_pub r
        Q..&&. BOLT8.handshake_remote_static r_res
                 Q.=== BOLT8.keypair_pub i
        Q..&&. there Q.=== Right m
        Q..&&. back Q.=== Right m
    send s r m = do
      (ct, _) <- BOLT8.encrypt s m
      fst <$> BOLT8.decrypt r ct

prop_size :: Q.Property
prop_size =
  Q.forAll gen_len $ \len ->
  Q.forAll Q.arbitrary $ \b ->
    let m = BS.replicate len b
    in  case spec_handshake of
          Left e -> Q.counterexample (show e) False
          Right (i_res, r_res) ->
            case BOLT8.encrypt (BOLT8.handshake_sender i_res) m of
              Left e -> Q.counterexample (show e) False
              Right (f, _) ->
                let r = BOLT8.handshake_receiver r_res
                in       BS.length f Q.=== len + 34
                  Q..&&. fmap fst (BOLT8.decrypt_header r (BS.take 18 f))
                           Q.=== Right (len + 16)
                  Q..&&. fmap fst (BOLT8.decrypt r f) Q.=== Right m
  where
    gen_len = Q.frequency [
        (1, pure 0)
      , (1, pure 65535)
      , (8, Q.choose (0, 65535))
      ]

prop_stream :: Q.Property
prop_stream =
  Q.forAll (Q.listOf (gen_bytes 512)) $ \ms ->
    case spec_handshake of
      Left e -> Q.counterexample (show e) False
      Right (i_res, r_res) ->
        let enc _ [] = Right []
            enc s (m : rest) = do
              (f, s') <- BOLT8.encrypt s m
              (f :) <$> enc s' rest
        in  case enc (BOLT8.handshake_sender i_res) ms of
              Left e -> Q.counterexample (show e) False
              Right fs ->
                consume (BOLT8.handshake_receiver r_res) (BS.concat fs)
                  Q.=== Right ms

prop_pub :: Q.Property
prop_pub = Q.forAll gen_secret $ \sec ->
  case BOLT8.keypair sec of
    Nothing -> Q.counterexample "keypair" False
    Just kp ->
      let pub = BOLT8.keypair_pub kp
      in  BOLT8.parse_pub (BOLT8.serialize_pub pub) Q.=== Just pub
