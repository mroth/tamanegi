package main

import (
	"crypto/rsa"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"runtime"
	"strings"
)

func main() {
	var threads = flag.Int("t", runtime.NumCPU(), "number of simultaneous hashing worker `threads`")
	var continuous = flag.Bool("c", false, "continuously search for multiple matches")
	var numMatches = flag.Int("n", 0, "quit after finding `num` matches (implies -c)")
	var output = flag.String("output", "", "write keys to filesystem `directory`")
	var prefix = flag.String("p", "", "search for hashes matching `prefix`")

	// bunch of boring manual CLI option parsing cleanup
	flag.Parse()
	*prefix = strings.ToUpper(*prefix) // normalize prefix to uppercase
	if *numMatches != 0 {
		*continuous = true
	}
	if *output != "" && !dirExists(*output) {
		fmt.Println("Output directory does not exist!:", *output)
		os.Exit(1)
	}

	// start up the worker threads
	results := make(chan *rsa.PrivateKey)
	for t := 1; t <= *threads; t++ {
		go KeyHasher(*prefix, results, t)
	}

	// here come the results!
	var matchesFound = 0
	for key := range results {
		matchesFound++
		onionName := strings.ToLower(OnionNameString(key))
		pem := encPrivKey(key)

		if *output == "" {
			// output to screen
			fmt.Printf("Found matching domain: %s.onion\n", onionName)
			fmt.Printf("%s\n", pem)
		} else {
			// output to disk
			filepath := path.Join(*output, onionName+".pem")
			err := ioutil.WriteFile(filepath, pem, 0644)

			if err == nil {
				log.Println("Saved matching domain for", onionName+".onion")
			} else {
				log.Fatal(err)
			}
		}

		if matchesFound == *numMatches || !*continuous {
			os.Exit(0)
		}
	}

}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsDir()
}
