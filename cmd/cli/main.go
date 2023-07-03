package main

import (
	"os"
	"time"

	"hrp/cmd"
)

func main() {
	defer func() {
		if err := recover(); err != nil {
			// report panic to sentry
			sentry.CurrentHub().Recover(err)
			sentry.Flush(time.Second * 5)

			// print panic trace
			panic(err)
		}
	}()

	exitCode := cmd.Execute()
	os.Exit(exitCode)
}
