package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	id := "12D3KooWN499RqNMPndYFwZ9WDYQW23UXHUj9fi7mWcntSSUXJiZ"
	data := id + "mailbox"
	hash := sha256.Sum256([]byte(data))
	fmt.Printf("ID: %s\n", id)
	fmt.Printf("Data: %s\n", data)
	fmt.Printf("Coord: %x\n", hash)
}
