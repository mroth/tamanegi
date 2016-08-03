package main

import (
	"log"
	"os"
)

func DebugLogF(format string, a ...interface{}) {
	if debugModeActive() {
		log.Printf(format, a...)
	}
}

func DebugLogLn(msgs ...interface{}) {
	if debugModeActive() {
		log.Println(msgs...)
	}
}

func debugModeActive() bool {
	d := os.Getenv("DEBUG")
	if d == "1" || d == "true" || d == "TRUE" {
		return true
	}
	return false
}
