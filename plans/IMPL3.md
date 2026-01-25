# IMPL3: Doc fixes and negative tests

## Steps
1) Update Haddock comments in encrypt/decrypt to say rotation at 1000.
2) Add tests in test/Main.hs:
   - act2 rejects wrong version.
   - act2 rejects wrong length.
   - act3/finalize reject invalid MAC (flip one byte in ciphertext).
   - decrypt rejects short packet.
3) Keep tests focused and deterministic.
