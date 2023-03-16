package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"

	"github.com/TheRebelOfBabylon/canoe"
)

var (
	testServerAddr = "localhost:5000"
)

func main() {
	cfg := &canoe.ClientConfig{Rand: rand.Reader}
	// get our own private key
	keyBytes, err := ioutil.ReadFile("client_private.pem")
	if err != nil {
		fmt.Println(err)
		return
	}
	privKey, err := canoe.ParsePrivateKey(keyBytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	cfg.AddHostKey(privKey)
	// get server pubkey
	encodedPubkeyBytes, err := ioutil.ReadFile("../server/server_public.pem")
	if err != nil {
		fmt.Println(err)
		return
	}
	pubkey, err := canoe.ParsePublicKey(encodedPubkeyBytes)
	if err != nil {
		fmt.Println(err)
		return
	}
	client, err := canoe.Dial(testServerAddr, pubkey, cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()
	err = client.SendFile("test.txt")
	if err != nil {
		fmt.Println(err)
		return
	}
}
