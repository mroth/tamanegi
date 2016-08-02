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

		// Enumerate possibilities for the public exponent of the public key, and
		// compute the onion hash for each and compare for a matching partial
		// collision.
		for e := E_MIN; e <= E_MAX; e += 2 {
			// key.PublicKey.E = e
			key.E = e
			name := OnionNameString(key)
			if strings.HasPrefix(name, *prefix) {
				// TODO: crazy wacky key munging?!
				// based on https://github.com/ChrisCalderon/PyShallot/blob/2922e00a66ea485ad723be2d1149f62ce6a083cb/shallot.py#L106-L129
				bE := new(big.Int).SetInt64(int64(e))
				pq := new(big.Int).Add(key.Primes[0], key.Primes[1])
				pq1 := new(big.Int).Sub(pq, big.NewInt(1))
				tot := new(big.Int).Sub(key.N, pq1)
				key.D = key.D.ModInverse(bE, tot)
				// NOTE: this tends to modify the keys so they pass valid check here,
				// but then trying to verify with `openssl rsa -in foo.pem -check` gets:
				// RSA key error: dmp1 not congruent to d
				// RSA key error: dmq1 not congruent to d

				// TODO: verify key validity
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
