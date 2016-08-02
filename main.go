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
	var threads = flag.Int("t", runtime.NumCPU(), "number of simultaneous hashing `threads`")
	var continuous = flag.Bool("c", false, "continuously search for multiple matches")
	var output = flag.String("output", "", "write keys to filesystem `directory`")
	var prefix = flag.String("p", "", "search for hashes matching `prefix`")

	flag.Parse()
	*prefix = strings.ToUpper(*prefix) // normalize prefix to uppercase
	if *output != "" && !dirExists(*output) {
		fmt.Println("Output directory does not exist!:", *output)
		os.Exit(1)
	}

	results := make(chan *rsa.PrivateKey)
	for t := 1; t <= *threads; t++ {
		go KeyHasher(*prefix, results)
	}

	for key := range results {
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
				log.Println("Stored matching domain for", onionName+".onion")
			} else {
				log.Fatal(err)
			}
		}

		if !*continuous {
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
