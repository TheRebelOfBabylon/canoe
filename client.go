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
	"os"
	"strings"
	"sync"
	"time"

	bg "github.com/SSSOCPaulCote/blunderguard"
)

const (
	ErrNoPrivateKey    = bg.Error("no private key found")
	ErrInvalidResponse = bg.Error("invalid response from server")
	ErrWeakSessionkey  = bg.Error("weak session key")
)

var (
	udpTimeout = 100 * time.Millisecond
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
	sync.WaitGroup
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
func (c *Client) send(pay []byte, msgType MsgTypes) error {
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
	return nil
}

// Close ends the TCP connection
func (c *Client) Close() error {
	return c.tcpConn.Close()
}

func (c *Client) SendFile(pathToFile string) error {
	// First let's ensure the file exists and get info on it
	info, err := os.Stat(pathToFile)
	if err != nil {
		return err
	}
	fmt.Printf("Creating packets for %v....\n", info.Name())
	packetQueue, err := createPackets(pathToFile, c.sessionKey)
	if err != nil {
		return err
	}
	fmt.Println("Packets created. Sending file transfer request...")
	// Build our put request
	init := PutFileTransferInit{
		FileName:        info.Name(),
		FileSize:        uint64(info.Size()),
		NumberOfPackets: uint32(len(packetQueue.Queue)),
	}
	initFrame := TransferFrame{
		Type:    PUT_FILE,
		Payload: init.Serialize(),
	}
	// Send the request
	err = c.send(initFrame.Serialize(), TRANSFER_INIT)
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
	} else if f.Type != TRANSFER_ACK {
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
	fmt.Println("Starting UDP connection....")
	// let's create a UDP client
	udpClient, err := NewUDPClient(c.tcpConn.RemoteAddr().(*net.TCPAddr).IP.String()+fmt.Sprintf(":%v", ack.UDPPort), c.sessionKey)
	if err != nil {
		return err
	}
	defer udpClient.Close()
	quitChan := make(chan struct{})
	c.Add(1)
	// handleAcks will update the packetQueue acked status whenever a packet ack is received
	// it will exit when the main sending loop exits
	fmt.Println("UDP connection established. Starting file transfer...")
	go c.handleAcks(packetQueue, quitChan)
	for {
		acked := 0
		for i, packet := range packetQueue.Queue {
			if !packet.Acked && packetQueue.CanSend(i, udpTimeout) {
				_, err := udpClient.conn.Write(packet.EncryptedPacket)
				if err != nil {
					close(quitChan)
					fmt.Println(err)
					packetQueue.RUnlock()
					return err
				}
				packetQueue.TimeSent(i, time.Now())
			} else if packet.Acked {
				acked += 1
			}
		}
		if acked == len(packetQueue.Queue) {
			close(quitChan)
			break
		}
	}
	c.Wait()
	fmt.Println("File transfer complete")
	return nil
}

// handleAcks is a dedicated goroutine for reading messages on the TCP connection and updating
// the packet queue ack statuses
func (c *Client) handleAcks(q *PacketQueue, quitChan chan struct{}) {
	defer c.Done()
	for {
		buffer := make([]byte, 4096)
		select {
		case <-quitChan:
			return
		default:
			_, err := c.tcpConn.Read(buffer)
			if err == io.EOF {
				return
			} else if err != nil {
				fmt.Println(err)
			}
			// parse the received data
			orderNumber, err := c.parsePacketAck(bytes.Trim(buffer, "\x00"))
			if err != nil {
				fmt.Println(err)
				return
			}
			// update the packets that have been acked
			if !q.IsAck(int(orderNumber - 1)) {
				q.Ack(int(orderNumber - 1))
			}
		}
	}
}

// parsePacketAck will parse the JSON bytes, decrypt and decode to get the list of packets that were acked
func (c *Client) parsePacketAck(b []byte) (uint32, error) {
	var f Frame
	err := json.Unmarshal(b, &f)
	if err != nil {
		return 0, err
	}
	if f.Type != PACKET_ACK {
		return 0, ErrInvalidResponse
	}
	// decode and decrypt payload
	decodedPay, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return 0, err
	}
	decryptedPay, err := DecryptAESGCM(decodedPay, c.sessionKey)
	if err != nil {
		return 0, err
	}
	// unmarshal json payload
	var ackFrame AckFrame
	err = json.Unmarshal(decryptedPay, &ackFrame)
	if err != nil {
		return 0, err
	}
	if ackFrame.Status != OK {
		return 0, ErrInvalidResponse
	}
	var packetAck PacketAck
	err = json.Unmarshal(ackFrame.Payload, &packetAck)
	if err != nil {
		return 0, err
	}
	return packetAck.OrderNumber, nil
}
