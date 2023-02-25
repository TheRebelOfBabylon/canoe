package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/TheRebelOfBabylon/canoe"
)

var (
	testServerAddr = "localhost:5000"
)

func main() {
	cfg := &canoe.ServerConfig{Rand: rand.Reader}
	// get our own private key
	keyBytes, err := ioutil.ReadFile("server_private.pem")
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
	server := canoe.NewServer(cfg)
	lis, err := net.Listen("tcp", testServerAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = server.Serve(lis)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer server.Close()
	fmt.Printf("Server listening on %v...\n", lis.Addr())
	time.Sleep(30 * time.Second)
}
