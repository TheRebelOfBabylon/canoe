package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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
	rawPubkeyBytes := x509.MarshalPKCS1PublicKey(pubkey)
	encodedPubkey := base64.StdEncoding.EncodeToString(rawPubkeyBytes)
	client, err := canoe.Dial(testServerAddr, encodedPubkey, cfg)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer client.Close()
	msg := canoe.TransferInit{
		FileSize:        69,
		FileName:        "boobies.txt",
		NumberOfPackets: 420,
	}
	err = client.Send(&canoe.Frame{Type: canoe.TRANSFER_INIT, Payload: msg.Serialize()})
	if err != nil {
		fmt.Println(err)
		return
	}
}
