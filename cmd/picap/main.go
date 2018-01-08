package main

import (
	"log"
	"os"

	"github.com/jaffee/commandeer/cobrafy"
	"github.com/pilosa/picap"
)

func main() {
	err := cobrafy.Execute(picap.NewMain())
	if err != nil {
		log.Fatalf("executing picap: %v", err)
		os.Exit(1)
	}
}
