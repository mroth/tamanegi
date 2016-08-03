package main

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"
)

func KeyHasher(prefix string, results chan *rsa.PrivateKey, workerNum int) {
	logPrefix := fmt.Sprintf("[Worker #%d]", workerNum)
	var bigOne = big.NewInt(1)
	var onionNameBuffer bytes.Buffer

	for {
		// Generate a new RSA keypair.
		//
		// It is possible for new key generation can fail, although the Go
		// documentation is silent on what might cause that to happen. So here,
		// for error handling we will just repeat trying until the operation
		// succeeds.
		key, err := NewKey()
		for err != nil {
			DebugLogLn(logPrefix, "Key generation failed!")
			key, err = NewKey()
		}
		DebugLogLn(logPrefix, "Generated new key, starting enumeration...")

		// Preset some variables outside of the inner loop, in order to avoid
		// new big.Int allocations, which are somewhat expensive.
		p, q := key.Primes[0], key.Primes[1]
		p1 := new(big.Int).Sub(p, bigOne) // p - 1
		q1 := new(big.Int).Sub(q, bigOne) // q - 1
		r0 := new(big.Int).Mul(p1, q1)    // (p-1)(q-1)
		bE := new(big.Int)                // placeholder for bigint copy of E

		// Enumerate possibilities for the public exponent of the public key, and
		// compute the onion hash for each and compare for a matching partial
		// collision. This method is known as "sloppy" key enumeration.
		for e := E_MIN; e <= E_MAX; e += 2 {
			key.E = e
			name := OnionNameStringFast(&onionNameBuffer, key)
			if strings.HasPrefix(name, prefix) {
				// Some code here (very roughly) based on FFP-0.0.8 rsa.c

				// We have a match!  Now we recalculate D
				//rsa->d = BN_mod_inverse(rsa->d, rsa->e, r0, ctx2);
				bE.SetInt64(int64(e))
				key.D.ModInverse(bE, r0)

				// Force recalculate d mod (p-1) [dmp1] and d mod (q-1) [dmq1]
				//
				// key.Precompute() could do this... because of !nil guard, would only
				// work if *certain* has not already called, because Precompute() will
				// silently return haveing done nothing if it detects dmp1 != nil.
				key.Precomputed.Dp.Mod(key.D, p1)
				key.Precomputed.Dq.Mod(key.D, q1)

				/* Verify key validity */
				// We were doing "sloppy" key generation for speed, so may still be
				// invalid even after we recalculate values.
				verificationErr := key.Validate()
				if verificationErr != nil {
					DebugLogF("%s found match %s (e=%d) / INVALID: %s\n", logPrefix, name, e, verificationErr)
				} else {
					DebugLogF("%s found match %s (e=%d) / VERIFIED", logPrefix, name, e)
					results <- key
					break
				}
			}
		}

	}
}
