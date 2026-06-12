package main

import (
	"encoding/base64"
	"fmt"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"os"
)

func main() {
	priv, _, _ := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	bytes, _ := crypto.MarshalPrivateKey(priv)
	fmt.Println("KEY:", base64.StdEncoding.EncodeToString(bytes))
	id, _ := peer.IDFromPrivateKey(priv)
	fmt.Println("ID:", id.String())
	os.WriteFile("relay.key.b64", bytes, 0644)
}
