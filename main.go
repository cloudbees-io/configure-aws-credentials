package main

import (
	"log"

	"github.com/cloudbees-io/configure-aws-credentials/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
