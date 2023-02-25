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
	"net"

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
func Dial(addr, pubkey string, config *ClientConfig) (*Client, error) {
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
		HandshakeKey: base64.StdEncoding.EncodeToString(handshakeKey),
		Payload:      base64.StdEncoding.EncodeToString(encryptedPubkey),
	}
	// Unmarshall server pubkey
	serverPubkeyBytes, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	serverPubkey, err := x509.ParsePKCS1PublicKey(serverPubkeyBytes)
	if err != nil {
		return nil, err
	}
	// encrypt Msg with server pubkey
	encryptedMsg, err := EncryptOAEP(sha256.New(), config.Rand, serverPubkey, []byte(msg.Serialize()), []byte(""))
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
	if f.Type != HANDSHAKE_ACK {
		return nil, ErrInvalidResponse
	}
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
	// deode decrypted msg
	decodedDecryptedPay, err := base64.StdEncoding.DecodeString(string(decryptedPay))
	if err != nil {
		return nil, err
	}
	// unmarshall ack
	var ack HandshakeAck
	err = json.Unmarshal(decodedDecryptedPay, &ack)
	if err != nil {
		return nil, err
	}
	// decrypt session key with client pubkey
	decodedEncryptedSessKey, err := base64.StdEncoding.DecodeString(ack.SessionKey)
	if err != nil {
		return nil, err
	}
	sesskey, err := DecryptOAEP(sha256.New(), config.Rand, config.privateKey, decodedEncryptedSessKey, []byte(""))
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
}

// Send sends a serialized message to the server
func (c *Client) Send(unencryptedFrame *Frame) error {
	encryptedPay, err := EncryptAESGCM([]byte(unencryptedFrame.Payload), c.sessionKey)
	if err != nil {
		return err
	}
	unencryptedFrame.Payload = base64.StdEncoding.EncodeToString(encryptedPay)
	_, err = c.tcpConn.Write(unencryptedFrame.Serialize())
	if err != nil {
		return err
	}
	// wait for response
	buffer := make([]byte, 4096)
	_, err = c.tcpConn.Read(buffer)
	if err != nil {
		return err
	}
	switch unencryptedFrame.Type {
	case TRANSFER_INIT:
		// then we expect a TransferAck
		// Parse what should be ACK
		// unmarshall json
		var f Frame
		err = json.Unmarshal(bytes.Trim(buffer, "\x00"), &f)
		if err != nil {
			return err
		}
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
		// deode decrypted msg
		decodedDecryptedPay, err := base64.StdEncoding.DecodeString(string(decryptedPay))
		if err != nil {
			return err
		}
		// unmarshall ack
		var ack TransferAck
		err = json.Unmarshal(decodedDecryptedPay, &ack)
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
