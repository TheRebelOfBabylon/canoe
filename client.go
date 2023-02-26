package canoe

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	bg "github.com/SSSOCPaulCote/blunderguard"
)

const (
	ErrNoPrivateKey    = bg.Error("no private key found")
	ErrInvalidResponse = bg.Error("invalid response from server")
	ErrWeakSessionkey  = bg.Error("weak session key")
)

type ClientConfig struct {
	privateKey *rsa.PrivateKey
	Rand       io.Reader
}

// AddHostKey is a method for registering a private key in the server config
func (c *ClientConfig) AddHostKey(key *rsa.PrivateKey) {
	c.privateKey = key
}

type Client struct {
	Version    uint8
	tcpConn    *net.TCPConn
	cfg        *ClientConfig
	sessionKey []byte
}

// Dial starts a client connection to the given canoe server. It is a convenience function to the given network address
// initiates the Seif handshake, and then sets up a Client.
func Dial(addr string, pubkey *rsa.PublicKey, config *ClientConfig) (*Client, error) {
	// Ensure PrivateKey is not nil
	if config.privateKey == nil {
		return nil, ErrNoKeyFound
	}
	Addr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTCP("tcp", nil, Addr)
	if err != nil {
		return nil, err
	}
	// Generate HandshakeKey
	handshakeKey := CreateAESKey()
	// marshall public key
	pubkeyBytes := x509.MarshalPKCS1PublicKey(&config.privateKey.PublicKey)
	// encrypt client pubkey with HandshakeKey
	encryptedPubkey, err := EncryptAESGCM(pubkeyBytes, handshakeKey)
	if err != nil {
		return nil, err
	}
	// encode encryptedPubkey and initialize HandshakeInit msg
	msg := HandshakeInit{
		Version:      defaultVersion,
		HandshakeKey: handshakeKey,
		Payload:      encryptedPubkey,
	}
	// Sign message
	sig, err := msg.Sign(config.privateKey, config.Rand)
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	// encrypt Msg with server pubkey
	encryptedMsg, err := EncryptOAEP(sha256.New(), config.Rand, pubkey, msg.Serialize(), []byte(""))
	if err != nil {
		return nil, err
	}
	// create frame
	frame := Frame{
		Type:    HANDSHAKE_INIT,
		Payload: base64.StdEncoding.EncodeToString(encryptedMsg),
	}
	// send to server
	_, err = conn.Write(frame.Serialize())
	if err != nil {
		return nil, err
	}
	// Wait for response
	buffer := make([]byte, 4096)
	_, err = conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	// Parse what should be ACK
	// unmarshall json
	var f Frame
	err = json.Unmarshal(bytes.Trim(buffer, "\x00"), &f)
	if err != nil {
		return nil, err
	}
	switch f.Type {
	case CLOSE:
		return nil, handleClose(&f, handshakeKey)
	case HANDSHAKE_ACK:
		// decode payload
		decodePay, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return nil, err
		}
		// decrypt with handshake key
		decryptedPay, err := DecryptAESGCM(decodePay, handshakeKey)
		if err != nil {
			return nil, err
		}
		// unmarshall ackframe
		var ackFrame AckFrame
		err = json.Unmarshal(decryptedPay, &ackFrame)
		if err != nil {
			return nil, err
		}
		if ackFrame.Status != OK {
			return nil, errors.New(string(ackFrame.Payload))
		}
		// unmarshall ack
		var ack HandshakeAck
		err = json.Unmarshal(ackFrame.Payload, &ack)
		if err != nil {
			return nil, err
		}
		// Verify server signature
		serialMsg := ack.serializeForSign()
		hashedMsg := sha256.Sum256(serialMsg)
		err = rsa.VerifyPSS(pubkey, crypto.SHA256, hashedMsg[:], ack.Signature, nil)
		if err != nil {
			return nil, err
		}
		sesskey, err := DecryptOAEP(sha256.New(), config.Rand, config.privateKey, ack.SessionKey, []byte(""))
		if err != nil {
			return nil, err
		}
		if len(sesskey) < 32 {
			return nil, ErrWeakSessionkey
		}
		return &Client{
			Version:    defaultVersion,
			tcpConn:    conn,
			cfg:        config,
			sessionKey: sesskey[:],
		}, nil
	default:
		return nil, ErrInvalidResponse
	}
}

func handleClose(f *Frame, key []byte) error {
	// Assume it's encrypted and encoded
	encryptedBytes, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil && strings.Contains(err.Error(), "illegal base64 data at input byte") {
		// assume it's clear text
		return errors.New(f.Payload)
	}
	decryptedBytes, err := DecryptAESGCM(encryptedBytes, key)
	if err != nil {
		return fmt.Errorf("error when decrypting close message: %v", err)
	}
	var ackFrame AckFrame
	err = json.Unmarshal(decryptedBytes, &ackFrame)
	if err != nil {
		return fmt.Errorf("error when unpacking json: %v", err)
	}
	return errors.New(string(ackFrame.Payload))
}

// Send sends a serialized message to the server
func (c *Client) Send(pay []byte, msgType MsgTypes) error {
	encryptedPay, err := EncryptAESGCM(pay, c.sessionKey)
	if err != nil {
		return err
	}
	frame := Frame{
		Type:    msgType,
		Payload: base64.StdEncoding.EncodeToString(encryptedPay),
	}
	_, err = c.tcpConn.Write(frame.Serialize())
	if err != nil {
		return err
	}
	// wait for response
	buffer := make([]byte, 4096)
	_, err = c.tcpConn.Read(buffer)
	if err != nil {
		return err
	}
	// unmarshall json
	var f Frame
	err = json.Unmarshal(bytes.Trim(buffer, "\x00"), &f)
	if err != nil {
		return err
	}
	if f.Type == CLOSE {
		return handleClose(&f, c.sessionKey)
	}
	switch frame.Type {
	case TRANSFER_INIT:
		// then we expect a TransferAck
		// Parse what should be ACK
		if f.Type != TRANSFER_ACK {
			return ErrInvalidResponse
		}
		// decode payload
		decodePay, err := base64.StdEncoding.DecodeString(f.Payload)
		if err != nil {
			return err
		}
		// decrypt with session key
		decryptedPay, err := DecryptAESGCM(decodePay, c.sessionKey)
		if err != nil {
			return err
		}
		// unmarshall ackframe
		var ackFrame AckFrame
		err = json.Unmarshal(decryptedPay, &ackFrame)
		if err != nil {
			return err
		}
		fmt.Println(ackFrame)
		if ackFrame.Status != OK {
			return errors.New(string(ackFrame.Payload))
		}
		// unmarshall ack
		var ack TransferAck
		err = json.Unmarshal(ackFrame.Payload, &ack)
		if err != nil {
			return err
		}
		fmt.Println(ack)
	}
	return nil
}

// Close ends the TCP connection
func (c *Client) Close() error {
	return c.tcpConn.Close()
}
