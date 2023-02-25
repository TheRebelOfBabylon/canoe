package canoe

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	bg "github.com/SSSOCPaulCote/blunderguard"
	"github.com/google/uuid"
)

const (
	ErrVersionMismatch  = bg.Error("protocol version mismatch")
	ErrWeakHandshakeKey = bg.Error("weak handshake key")
)

var (
	defaultVersion uint8  = 0
	defaultUDPPort uint16 = 6969
)

type ServerConfig struct {
	privateKey *rsa.PrivateKey
	Rand       io.Reader
}

// AddHostKey is a method for registering a private key in the server config
func (s *ServerConfig) AddHostKey(key *rsa.PrivateKey) {
	s.privateKey = key
}

type Server struct {
	Version   uint8
	tcpLis    net.Listener
	quit      chan struct{}
	closeConn map[string]chan struct{}
	wg        sync.WaitGroup
	cfg       *ServerConfig
}

// NewServer creates a new instance of Server
func NewServer(config *ServerConfig) *Server {
	return &Server{
		Version:   defaultVersion,
		quit:      make(chan struct{}),
		closeConn: make(map[string]chan struct{}, 0),
		wg:        sync.WaitGroup{},
		cfg:       config,
	}
}

// handleMsg will take the TCP message, decode and decrypt as necessary and then create the appropriate response
func (s *Server) handleMsg(msgBytes []byte, sessionKey []byte) ([]byte, error) {
	var (
		f Frame
	)
	err := json.Unmarshal(bytes.Trim(msgBytes, "\x00"), &f)
	if err != nil {
		return nil, err
	}
	// base64 decode Payload
	encryptedPay, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return nil, err
	}
	switch f.Type {
	case HANDSHAKE_INIT:
		// decrypt payload
		rawPay, err := DecryptOAEP(sha256.New(), s.cfg.Rand, s.cfg.privateKey, encryptedPay, []byte(""))
		if err != nil {
			return nil, err
		}
		// decode decrypted paylaod
		decodedRawPay, err := base64.StdEncoding.DecodeString(string(rawPay))
		if err != nil {
			return nil, err
		}
		// unmarshall
		// check for version compatibility
		msg := HandshakeInit{}
		err = json.Unmarshal(decodedRawPay, &msg)
		if err != nil {
			return nil, err
		}
		// check version compatibility
		if msg.Version != s.Version {
			return []byte{}, ErrVersionMismatch
		}
		// decode handshakekey
		rawHK, err := base64.StdEncoding.DecodeString(msg.HandshakeKey)
		if err != nil {
			return []byte{}, err
		}
		// check if handshake key is at minimum 256 bits
		if len(rawHK) < 32 {
			return []byte{}, ErrWeakHandshakeKey
		}
		// decode encrypted pubkey
		encryptedPubkey, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			return []byte{}, err
		}
		pubkeyBytes, err := DecryptAESGCM(encryptedPubkey, rawHK)
		if err != nil {
			return []byte{}, err
		}
		// encrypt session key with client pubkey
		pubkey, err := x509.ParsePKCS1PublicKey(pubkeyBytes)
		if err != nil {
			return []byte{}, err
		}
		encryptedSessKey, err := EncryptOAEP(sha256.New(), s.cfg.Rand, pubkey, sessionKey, []byte(""))
		if err != nil {
			return []byte{}, err
		}
		// make HandshakeAck message and serialize
		ack := HandshakeAck{
			SessionKey: base64.StdEncoding.EncodeToString(encryptedSessKey),
			UDPPort:    defaultUDPPort,
		}
		// Encrypt payload with handshake key
		encryptedPayload, err := EncryptAESGCM([]byte(ack.Serialize()), rawHK)
		if err != nil {
			return []byte{}, err
		}
		frame := &Frame{
			Type:    HANDSHAKE_ACK,
			Payload: base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		return frame.Serialize(), nil
	case TRANSFER_INIT:
		// decrypt payload using session key
		rawPay, err := DecryptAESGCM(encryptedPay, sessionKey)
		if err != nil {
			return []byte{}, err
		}
		// decode decrypted paylaod
		decodedRawPay, err := base64.StdEncoding.DecodeString(string(rawPay))
		if err != nil {
			return nil, err
		}
		// unmarshall
		msg := TransferInit{}
		err = json.Unmarshal(decodedRawPay, &msg)
		if err != nil {
			return []byte{}, err
		}
		// TODO - Implement this
		fmt.Println(msg)
		// Make TransferAck
		ack := TransferAck{
			Status: OK,
		}
		// Encrypt payload with session key
		encryptedPayload, err := EncryptAESGCM([]byte(ack.Serialize()), sessionKey)
		if err != nil {
			return []byte{}, err
		}
		frame := &Frame{
			Type:    TRANSFER_ACK,
			Payload: base64.StdEncoding.EncodeToString(encryptedPayload),
		}
		return frame.Serialize(), nil
	}
	return []byte{}, nil
}

// handleConnection is run as a go routine for every new connection
func (s *Server) handleConnection(conn net.Conn, connId string) {
	defer func() {
		conn.Close()
		s.wg.Done()
	}()
	// create session key
	sessionKey := CreateAESKey()
loop:
	for {
		buffer := make([]byte, 4096)
		select {
		case <-s.closeConn[connId]:
			return
		default:
			_, err := conn.Read(buffer)
			if err != nil {
				log.Println(err)
				break loop
			}
			resp, err := s.handleMsg(buffer[:], sessionKey)
			if err != nil {
				log.Println(err)
				continue loop
			}
			_, err = conn.Write(resp)
			if err != nil {
				log.Println(err)
				break loop
			}
		}
	}

}

// handleRequests is run as a goroutine to handle every new connection request
func (s *Server) handleRequests() {
	for {
		select {
		case <-s.quit:
			return
		default:
			conn, err := s.tcpLis.Accept()
			if err != nil {
				log.Println(err)
			}
			id := uuid.New()
			s.closeConn[id.String()] = make(chan struct{})
			s.wg.Add(1)
			go s.handleConnection(conn, id.String())
		}
	}
}

// Serve creates a new go routine to start handling connection requests
func (s *Server) Serve(lis net.Listener) error {
	s.tcpLis = lis
	go s.handleRequests()
	return nil
}

// Close safely closes the server
func (s *Server) Close() error {
	close(s.quit)
	for _, channel := range s.closeConn {
		close(channel)
	}
	s.wg.Wait()
	if s.tcpLis != nil {
		return s.tcpLis.Close()
	}
	return nil
}
