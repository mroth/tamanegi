package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

func main() {
	var threads = flag.Int("t", runtime.NumCPU(), "number of simultaneous hashing `threads`")
	var continuous = flag.Bool("c", false, "continuously search for multiple matches")
	var output = flag.String("output", "", "write keys to filesystem `directory` *TODO*")
	var prefix = flag.String("p", "", "search for hashes matching `prefix`")

	flag.Parse()
	*prefix = strings.ToUpper(*prefix) // normalize prefix to uppercase

	results := make(chan *rsa.PrivateKey)
	for t := 1; t <= *threads; t++ {
		go KeyHasher(*prefix, results)
	}

	for key := range results {
		fmt.Printf("Found matching domain: %s.onion\n", strings.ToLower(OnionNameString(key)))

		if *output == "" {
			fmt.Println(string(encPrivKey(key)))
		} else {
			// TODO: if in Output mode, write PEM to file instead of stdout
		}

		if !*continuous {
			os.Exit(0)
		}
	}

}
