package main

import (
	"fmt"
	"log"

	"github.com/joybiswas007/remote-wv-go/internal/database"
)

func main() {
	db := database.New()

	sudoers, err := db.OP()
	if err != nil {
		log.Fatal(err)
	}

	for _, sudoer := range sudoers {
		fmt.Printf("%v\n", sudoer.Passkey)
	}

	defer func() {
		db.Close()
	}()
}
