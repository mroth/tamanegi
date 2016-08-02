package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"
	"strings"
)

var threads = flag.Int("t", runtime.NumCPU(), "number of simultaneous hashing `threads`")
var continuous = flag.Bool("c", false, "continuously search for multiple matches")
var output = flag.String("output", "", "write keys to filesystem `directory` *TODO*")
var prefix = flag.String("p", "", "search for hashes matching `prefix`")

func KeyHasher(results chan *rsa.PrivateKey) {
	var bigOne = big.NewInt(1)

	for {
		// Generate a new RSA keypair.
		//
		// It is possible for new key generation can fail, although the Go
		// documentation is silent on what might cause that to happen. So here,
		// for error handling we will just repeat trying until the operation
		// succeeds.
		key, err := NewKey()
		for err != nil {
			fmt.Println("Something went horribly wrong!") // TODO: log on verbose
			key, err = NewKey()
		}

		// Preset some variables outside of the inner loop, in order to avoid
		// unncessary big.Int allocations.
		p, q := key.Primes[0], key.Primes[1]
		p1 := new(big.Int).Sub(p, bigOne) // p - 1
		q1 := new(big.Int).Sub(q, bigOne) // q - 1
		r0 := new(big.Int).Mul(p1, q1)    // (p-1)(q-1)

		// Enumerate possibilities for the public exponent of the public key, and
		// compute the onion hash for each and compare for a matching partial
		// collision.
		//
		// This method is known as "sloppy" key enumeration, we could be more
		// accurate by ***TODO write explanation
		for e := E_MIN; e <= E_MAX; e += 2 {
			key.E = e
			name := OnionNameString(key)
			if strings.HasPrefix(name, *prefix) {
				// Some code here (very roughly) based on FFP-0.0.8 rsa.c

				// We have a match!  Now we recalculate D
				//rsa->d = BN_mod_inverse(rsa->d, rsa->e, r0, ctx2);
				bE := new(big.Int).SetInt64(int64(e))
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
					log.Printf("match %s with e=%d has verification error: %s\n", name, e, verificationErr)
				} else {
					log.Printf("match %s with e=%d is VERIFIED", name, e)
					results <- key
					break
				}
			}
		}

	}
}

func main() {
	flag.Parse()
	*prefix = strings.ToUpper(*prefix) // normalize prefix to uppercase

	results := make(chan *rsa.PrivateKey)
	for t := 1; t <= *threads; t++ {
		go KeyHasher(results)
	}

	for key := range results {
		fmt.Printf("Found matching domain: %s.onion\n", OnionNameString(key))
		fmt.Println(string(encPrivKey(key)))
		// TODO: if in Output mode, write PEM to file instead of stdout

		if !*continuous {
			os.Exit(0)
		}
	}

}
