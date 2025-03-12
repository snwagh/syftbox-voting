package main

import (
	"fmt"
	"crypto/sha256"
	"encoding/hex"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// printKeyInfo prints a human-readable representation of a key
func printKeyInfo(key interface{}, label string) {
	fmt.Printf("\n%s:\n", label)
	
	switch k := key.(type) {
	case *rlwe.SecretKey:
		// Generate a simple hash of the first few coefficients as an ID
		hash := sha256.New()
		coeffs := k.Value.Q.Coeffs[0]
		for i := 0; i < 10 && i < len(coeffs); i++ {
			hash.Write([]byte(fmt.Sprintf("%d", coeffs[i])))
		}
		keyID := hash.Sum(nil)
		
		// Print the key ID as hex
		fmt.Printf("  Key ID: %s\n", hex.EncodeToString(keyID[:8]))
		
		// Print some coefficients from the secret key polynomial
		fmt.Printf("  Sample coefficients (first 10):\n")
		for i := 0; i < 10 && i < len(coeffs); i++ {
			fmt.Printf("    [%d]: %d\n", i, coeffs[i])
		}
		
	case *rlwe.PublicKey:
		// Generate a simple hash of the first few coefficients as an ID
		hash := sha256.New()
		coeffs0 := k.Value[0].Q.Coeffs[0]
		for i := 0; i < 10 && i < len(coeffs0); i++ {
			hash.Write([]byte(fmt.Sprintf("%d", coeffs0[i])))
		}
		keyID := hash.Sum(nil)
		
		// Print the key ID as hex
		fmt.Printf("  Key ID: %s\n", hex.EncodeToString(keyID[:8]))
		
		// Print some coefficients from the public key polynomials
		fmt.Printf("  Sample coefficients from first polynomial (first 10):\n")
		for i := 0; i < 10 && i < len(coeffs0); i++ {
			fmt.Printf("    [%d]: %d\n", i, coeffs0[i])
		}
		
		fmt.Printf("  Sample coefficients from second polynomial (first 10):\n")
		coeffs1 := k.Value[1].Q.Coeffs[0]
		for i := 0; i < 10 && i < len(coeffs1); i++ {
			fmt.Printf("    [%d]: %d\n", i, coeffs1[i])
		}
		
	case multiparty.PublicKeyGenShare:
		// Print some coefficients from the share polynomial
		fmt.Printf("  Sample coefficients (first 10):\n")
		coeffs := k.Value.Q.Coeffs[0]
		for i := 0; i < 10 && i < len(coeffs); i++ {
			fmt.Printf("    [%d]: %d\n", i, coeffs[i])
		}
	}
}

func main() {
	// Number of parties
	numParties := 3

	// Step 1: Set up parameters for the cryptosystem
	// Using a small example parameter set for demonstration
	// Using one of the example parameter sets from Lattigo
	paramsLit := rlwe.ParametersLiteral{
		LogN:     14,                // Ring degree (2^14 = 16384)
		Q:        []uint64{0x10000000006e0001},  // Moduli chain for ciphertext (valid NTT-friendly prime)
		P:        []uint64{0x10000140001},       // Special moduli for key-switching (valid NTT-friendly prime)
		Xe:       ring.Ternary{P: 0.5},    // Error distribution
		Xs:       ring.Ternary{P: 0.5},    // Secret key distribution
		RingType: ring.Standard,     // Standard ring (not conjugate-invariant)
	}

	params, err := rlwe.NewParametersFromLiteral(paramsLit)
	if err != nil {
		panic(err)
	}

	fmt.Println("Parameters initialized:")
	fmt.Printf("  - Ring degree (N): %d\n", 1<<params.LogN())
	fmt.Printf("  - Moduli chain (Q): %v\n", params.Q())
	fmt.Printf("  - Special moduli (P): %v\n", params.P())

	// Step 2: Initialize key generator and generate secret keys for each party
	keyGen := rlwe.NewKeyGenerator(params)
	
	secretKeys := make([]*rlwe.SecretKey, numParties)
	for i := 0; i < numParties; i++ {
		secretKeys[i] = keyGen.GenSecretKeyNew()
		printKeyInfo(secretKeys[i], fmt.Sprintf("Secret Key for Party %d", i+1))
	}

	// Step 3: Initialize the collective public key generation protocol
	pkgProtocols := make([]multiparty.PublicKeyGenProtocol, numParties)
	for i := range pkgProtocols {
		if i == 0 {
			pkgProtocols[i] = multiparty.NewPublicKeyGenProtocol(params)
		} else {
			pkgProtocols[i] = pkgProtocols[0].ShallowCopy()
		}
	}

	// Step 4: Generate a common random polynomial (CRP)
	crs, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}
	crp := pkgProtocols[0].SampleCRP(crs)

	// Step 5: Each party generates its share of the public key
	shares := make([]multiparty.PublicKeyGenShare, numParties)
	for i := range shares {
		shares[i] = pkgProtocols[i].AllocateShare()
		pkgProtocols[i].GenShare(secretKeys[i], crp, &shares[i])
		printKeyInfo(shares[i], fmt.Sprintf("Public Key Share for Party %d", i+1))
	}

	// Step 6: Aggregate all shares to form the collective public key
	aggregatedShare := pkgProtocols[0].AllocateShare()
	pkgProtocols[0].AggregateShares(shares[0], shares[1], &aggregatedShare)
	for i := 2; i < numParties; i++ {
		pkgProtocols[0].AggregateShares(aggregatedShare, shares[i], &aggregatedShare)
	}
	printKeyInfo(aggregatedShare, "Aggregated Public Key Share")

	// Step 7: Generate the collective public key
	collectivePK := rlwe.NewPublicKey(params)
	pkgProtocols[0].GenPublicKey(aggregatedShare, crp, collectivePK)
	printKeyInfo(collectivePK, "Collective Public Key")

	// Print the collective secret key (for demonstration purposes only)
	// In a real distributed setting, no party would know the collective secret key
	collectiveSK := rlwe.NewSecretKey(params)
	for i := 0; i < numParties; i++ {
		params.RingQP().Add(collectiveSK.Value, secretKeys[i].Value, collectiveSK.Value)
	}
	printKeyInfo(collectiveSK, "Collective Secret Key (would not be known in a real distributed setting)")

	fmt.Println("\nDistributed key generation completed successfully!")

	// =====================================================================
	// PART 2: Encryption, Homomorphic Addition, and Distributed Decryption
	// =====================================================================
	fmt.Println("\n\n=== ENCRYPTION, HOMOMORPHIC ADDITION, AND DISTRIBUTED DECRYPTION ===")

	// Initialize BGV scheme with the parameters
	bgvParams, err := bgv.NewParametersFromLiteral(bgv.ParametersLiteral{
		LogN:             params.LogN(),
		Q:                params.Q(),
		P:                params.P(),
		PlaintextModulus: 257, // t = 257, a prime number
	})
	if err != nil {
		panic(err)
	}

	// Create a BGV encoder
	encoder := bgv.NewEncoder(bgvParams)

	// Create an encryptor using the collective public key
	encryptor := bgv.NewEncryptor(bgvParams, collectivePK)

	// Create an evaluator for homomorphic operations
	evaluator := bgv.NewEvaluator(bgvParams, nil)

	// Create a decryptor using the collective secret key (for verification only)
	// In a real distributed setting, no single party would have this
	decryptor := bgv.NewDecryptor(bgvParams, collectiveSK)

	// Values to encrypt
	value1 := uint64(123)
	value2 := uint64(456)
	fmt.Printf("\nValue 1: %d\n", value1)
	fmt.Printf("Value 2: %d\n", value2)
	expectedSum := (value1 + value2) % bgvParams.PlaintextModulus()
	fmt.Printf("Expected sum (mod %d): %d\n", bgvParams.PlaintextModulus(), expectedSum)

	// Encode and encrypt the values
	plaintext1 := bgv.NewPlaintext(bgvParams, 0)
	plaintext2 := bgv.NewPlaintext(bgvParams, 0)
	
	// Encode the values into plaintexts
	encoder.Encode([]uint64{value1}, plaintext1)
	encoder.Encode([]uint64{value2}, plaintext2)

	// Encrypt the plaintexts
	ciphertext1 := bgv.NewCiphertext(bgvParams, 1, 0)
	ciphertext2 := bgv.NewCiphertext(bgvParams, 1, 0)
	encryptor.Encrypt(plaintext1, ciphertext1)
	encryptor.Encrypt(plaintext2, ciphertext2)

	fmt.Println("\nValues encrypted successfully")

	// Homomorphic addition
	ciphertextSum := bgv.NewCiphertext(bgvParams, 1, 0)
	evaluator.Add(ciphertext1, ciphertext2, ciphertextSum)
	fmt.Println("\nHomomorphic addition performed")

	// Verify the result using the collective secret key (for demonstration only)
	plaintextSum := bgv.NewPlaintext(bgvParams, 0)
	decryptor.Decrypt(ciphertextSum, plaintextSum)
	decryptedValues := make([]uint64, 1)
	encoder.Decode(plaintextSum, decryptedValues)
	decryptedSum := decryptedValues[0]
	fmt.Printf("\nDecrypted sum using collective secret key: %d\n", decryptedSum)

	// =====================================================================
	// PART 3: Distributed Decryption
	// =====================================================================
	fmt.Println("\n\n=== DISTRIBUTED DECRYPTION ===")

	// Initialize the key switching protocol for each party
	// This is used for distributed decryption
	noiseFlooding := ring.DiscreteGaussian{Sigma: 8, Bound: 64}
	keySwitchProtos := make([]multiparty.KeySwitchProtocol, numParties)
	for i := range keySwitchProtos {
		var err error
		keySwitchProtos[i], err = multiparty.NewKeySwitchProtocol(bgvParams, noiseFlooding)
		if err != nil {
			panic(err)
		}
	}

	// Create a zero secret key for the output of key switching (decryption)
	zeroSK := rlwe.NewSecretKey(bgvParams)

	// Each party generates its decryption share
	decryptShares := make([]multiparty.KeySwitchShare, numParties)
	for i := 0; i < numParties; i++ {
		decryptShares[i] = keySwitchProtos[i].AllocateShare(ciphertextSum.Level())
		keySwitchProtos[i].GenShare(secretKeys[i], zeroSK, ciphertextSum, &decryptShares[i])
		fmt.Printf("\nParty %d generated its decryption share\n", i+1)
	}

	// Aggregate the decryption shares
	aggregatedDecryptShare := keySwitchProtos[0].AllocateShare(ciphertextSum.Level())
	keySwitchProtos[0].AggregateShares(decryptShares[0], decryptShares[1], &aggregatedDecryptShare)
	for i := 2; i < numParties; i++ {
		keySwitchProtos[0].AggregateShares(aggregatedDecryptShare, decryptShares[i], &aggregatedDecryptShare)
	}
	fmt.Println("\nDecryption shares aggregated")

	// Finalize the decryption
	plaintextDistributed := bgv.NewPlaintext(bgvParams, 0)
	
	// Create a temporary ciphertext to hold the result of key switching
	ctOut := ciphertextSum.CopyNew()
	
	// Apply the key switching to get the decryption
	keySwitchProtos[0].KeySwitch(ciphertextSum, aggregatedDecryptShare, ctOut)
	
	// The result of key switching should be a ciphertext with c1 = 0, so c0 = plaintext + v
	// where v is a small noise. We can extract c0 as the plaintext.
	// Copy the first polynomial of the ciphertext to the plaintext
	for i := range ctOut.Value[0].Coeffs {
		plaintextDistributed.Value.Coeffs[i] = ctOut.Value[0].Coeffs[i]
	}
	
	// Decode the result
	decryptedDistributedValues := make([]uint64, 1)
	encoder.Decode(plaintextDistributed, decryptedDistributedValues)
	decryptedDistributedSum := decryptedDistributedValues[0]
	fmt.Printf("\nDecrypted sum using distributed decryption: %d\n", decryptedDistributedSum)

	// Verify the result
	if decryptedDistributedSum == expectedSum {
		fmt.Println("\nDistributed decryption successful! The result matches the expected sum.")
	} else {
		fmt.Printf("\nDistributed decryption error! Expected %d but got %d\n", expectedSum, decryptedDistributedSum)
	}
} 