package canoe

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	bg "github.com/SSSOCPaulCote/blunderguard"
	"github.com/google/uuid"
)

const (
	ErrVersionMismatch  = bg.Error("protocol version mismatch")
	ErrWeakHandshakeKey = bg.Error("weak handshake key")
	ErrUnsupportedType  = bg.Error("unsupported transfer type")
	ErrFileTooLarge     = bg.Error("file size is too large")
)

var (
	defaultVersion uint8  = 0
	defaultUDPPort uint16 = 6969
)

type ServerConfig struct {
	privateKey *rsa.PrivateKey
	Rand       io.Reader
	WorkingDir string
}

// AddHostKey is a method for registering a private key in the server config
func (s *ServerConfig) AddHostKey(key *rsa.PrivateKey) {
	s.privateKey = key
}

type (
	Server struct {
		Version   uint8
		tcpLis    net.Listener
		quit      chan struct{}
		closeConn map[string]chan struct{}
		wg        sync.WaitGroup
		cfg       *ServerConfig
	}
	AckQueue struct {
		queue     []uint32
		listeners map[string]*QueueListener
		sync.RWMutex
	}
)

// NewAckQueue creates an instance of the AckQueue
func NewAckQueue() *AckQueue {
	return &AckQueue{
		queue:     []uint32{},
		listeners: make(map[string]*QueueListener),
	}
}

// Push adds a new item to the queue
func (q *AckQueue) Push(v int) {
	q.Lock()
	defer q.Unlock()
	q.queue = append(q.queue, uint32(v))
	newListenerMap := make(map[string]*QueueListener)
	for n, l := range q.listeners {
		if !l.IsConnected {
			close(l.Signal)
			continue
		}
		l.Signal <- len(q.queue) + 1 // + 1 because then the subscriber can know when the channel is closed (if they receive 0)
		newListenerMap[n] = l
	}
	q.listeners = newListenerMap
}

// Pop removes the first item in the queue and returns its value
func (q *AckQueue) Pop() uint32 {
	q.Lock()
	defer q.Unlock()
	var item uint32
	if len(q.queue) > 0 {
		item = q.queue[0]
		q.queue = q.queue[1:]
	} else {
		q.queue = []uint32{}
	}
	return item
}

// Subscribe returns a channel which will have signals sent when a new item is pushed as well as an unsub function
func (q *AckQueue) Subscribe(name string) (chan int, func(), error) {
	q.Lock()
	defer q.Unlock()
	if _, ok := q.listeners[name]; ok {
		return nil, nil, ErrAlreadySubscribed
	}
	q.listeners[name] = &QueueListener{IsConnected: true, Signal: make(chan int, 2)}
	unsub := func() {
		q.Lock()
		defer q.Unlock()
		q.listeners[name].IsConnected = false
	}
	return q.listeners[name].Signal, unsub, nil
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
func (s *Server) handleMsg(msgBytes []byte, sessionKey []byte, conn net.Conn, connId string) (MsgTypes, []byte, error) {
	var (
		f     Frame
		frame Frame
		fType MsgTypes
	)
	err := json.Unmarshal(bytes.Trim(msgBytes, "\x00"), &f)
	if err != nil {
		return CLOSE, nil, err
	}
	// base64 decode Payload
	encryptedPay, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return CLOSE, nil, err
	}
	switch f.Type {
	case HANDSHAKE_INIT:
		// decrypt payload
		rawPay, err := DecryptOAEP(sha256.New(), s.cfg.Rand, s.cfg.privateKey, encryptedPay, []byte(""))
		if err != nil {
			return createErrCloseFrameHandshake(err)
		}
		// unmarshall
		// check for version compatibility
		msg := HandshakeInit{}
		err = json.Unmarshal(rawPay, &msg)
		if err != nil {
			return createErrCloseFrameHandshake(err)
		}
		// check version compatibility
		if msg.Version != s.Version {
			return createErrCloseFrameHandshake(ErrVersionMismatch)
		}
		// check if handshake key is at minimum 256 bits
		if len(msg.HandshakeKey) < 32 {
			return createErrCloseFrameHandshake(ErrWeakHandshakeKey)
		}
		pubkeyBytes, err := DecryptAESGCM(msg.Payload, msg.HandshakeKey)
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		// encrypt session key with client pubkey and verify client signature
		pubkey, err := x509.ParsePKCS1PublicKey(pubkeyBytes)
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		// verify client signature
		serialMsg := msg.serializeForSign()
		hashedMsg := sha256.Sum256(serialMsg)
		err = rsa.VerifyPSS(pubkey, crypto.SHA256, hashedMsg[:], msg.Signature, nil)
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		encryptedSessKey, err := EncryptOAEP(sha256.New(), s.cfg.Rand, pubkey, sessionKey[:], []byte(""))
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		// make HandshakeAck message, sign and serialize
		ack := HandshakeAck{
			SessionKey: encryptedSessKey,
		}
		sig, err := ack.Sign(s.cfg.privateKey, s.cfg.Rand)
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		ack.Signature = sig[:]
		// Wrap ack in the AckFrame
		ackFrame := AckFrame{
			Status:  OK,
			Payload: ack.Serialize(),
		}
		// Encrypt ackFrame with handshake key
		encryptedAckFrame, err := EncryptAESGCM(ackFrame.Serialize(), msg.HandshakeKey)
		if err != nil {
			return createErrCloseFrame(err, msg.HandshakeKey)
		}
		// encode encrypted ackFrame
		fType = HANDSHAKE_ACK
		frame.Type = HANDSHAKE_ACK
		frame.Payload = base64.StdEncoding.EncodeToString(encryptedAckFrame)
	case TRANSFER_INIT:
		// decrypt payload using session key
		rawPay, err := DecryptAESGCM(encryptedPay, sessionKey)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		// unmarshall
		msg := TransferFrame{}
		err = json.Unmarshal(rawPay, &msg)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		// check transfer type
		if msg.Type != PUT_FILE {
			return createErrCloseFrame(ErrUnsupportedType, sessionKey)
		}
		// unmarshall init
		init := PutFileTransferInit{}
		err = json.Unmarshal(msg.Payload, &init)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		// ensure our working dir has space for this file
		freeSpace, err := GetDirAvailableSpace(s.cfg.WorkingDir)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		if freeSpace < init.FileSize {
			return createErrCloseFrame(ErrFileTooLarge, sessionKey)
		}
		// Ensure our working dir doesn't already have a file with that name
		if _, err := os.Open(filepath.Join(s.cfg.WorkingDir, init.FileName)); err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		// Start up a UDP server
		// create AckQueue
		ackQueue := NewAckQueue()
		udp := NewUDPServer(sessionKey, init.NumberOfPackets, s.cfg.WorkingDir)
		err = udp.ListenAndServe(defaultUDPPort, init.FileName, ackQueue)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		quitChan := make(chan struct{})
		s.closeConn[connId+"sendAck"] = quitChan
		// goroutine to sendAcks
		go s.sendAcks(ackQueue, init.NumberOfPackets, conn, connId, sessionKey, quitChan)
		// Make TransferAck
		ack := TransferAck{
			UDPPort: defaultUDPPort,
		}
		// Wrap ack in the AckFrame
		ackFrame := AckFrame{
			Status:  OK,
			Payload: ack.Serialize(),
		}
		// Encrypt payload with session key
		encryptedPayload, err := EncryptAESGCM(ackFrame.Serialize(), sessionKey)
		if err != nil {
			return createErrCloseFrame(err, sessionKey)
		}
		fType = TRANSFER_ACK
		frame.Type = TRANSFER_ACK
		frame.Payload = base64.StdEncoding.EncodeToString(encryptedPayload)
	}
	return fType, frame.Serialize(), nil
}

// createAckPacket creates the serialized and encrypted ack packet for a given received packet
func createAckPacket(orderNum uint32, sessionKey []byte) ([]byte, error) {
	ackPacket := PacketAck{
		OrderNumber: orderNum,
	}
	ackFrame := AckFrame{
		Status:  OK,
		Payload: ackPacket.Serialize(),
	}
	encryptedAck, err := EncryptAESGCM(ackFrame.Serialize(), sessionKey)
	if err != nil {
		return nil, err
	}
	encodedAck := base64.StdEncoding.EncodeToString(encryptedAck)
	frame := Frame{
		Type:    PACKET_ACK,
		Payload: encodedAck,
	}
	return frame.Serialize(), nil
}

// sendAcks is the dedicated goroutine for sending acks whenever the ack queue is updated
func (s *Server) sendAcks(q *AckQueue, numOfPackets uint32, conn net.Conn, connId string, sessionKey []byte, quitChan chan struct{}) {
	defer s.wg.Done()
	// first let's make a map of ints and bools to keep track of which packets have been acked or not
	ackMap := make(map[int]bool)
	for i := 1; i != int(numOfPackets)+1; i++ {
		ackMap[i] = false
	}
	// subscribe to AckQueue
	sigChan, unsub, err := q.Subscribe(connId)
	if err != nil {
		// TODO - Integrate a way to send error messages back to main handler
		return
	}
	defer unsub()
	// main loop for listening for
loop:
	for {
		select {
		case k := <-sigChan:
			for j := 0; j < k; j++ {
				v := q.Pop()
				ackBytes, err := createAckPacket(v, sessionKey)
				if err != nil {
					return
				}
				_, err = conn.Write(ackBytes)
				if err != nil {
					return
				}
				ackMap[int(v)] = true
			}
		case <-quitChan:
			return
		default:
			// if all the values are true then exit
			for _, v := range ackMap {
				if !v {
					continue loop
				}
			}
			return
		}
	}
}

// createErrCloseFrameHandshake creates an unencrypted CLOSE message for the client
// that contains an error status. It is used during the handshake phase
func createErrCloseFrameHandshake(err error) (MsgTypes, []byte, error) {
	return CLOSE, Frame{
		Type:    CLOSE,
		Payload: err.Error(),
	}.Serialize(), err
}

// createErrCloseFrame creates a CLOSE message for the client that contains an error status
func createErrCloseFrame(ogErr error, key []byte) (MsgTypes, []byte, error) {
	// Create an error ack frame
	ackFrame := AckFrame{
		Status:  ERROR,
		Payload: []byte(ogErr.Error()),
	}
	// encrypt
	encryptedAck, err := EncryptAESGCM(ackFrame.Serialize(), key)
	if err != nil {
		return CLOSE, nil, err
	}
	// Wrap in a frame
	return CLOSE, Frame{
		Type:    CLOSE,
		Payload: base64.StdEncoding.EncodeToString(encryptedAck),
	}.Serialize(), ogErr
}

// handleConnection is run as a go routine for every new connection
func (s *Server) handleConnection(conn net.Conn, connId string) {
	defer s.wg.Done()
	// create session key
	sessionKey := CreateAESKey()
loop:
	for {
		buffer := make([]byte, 4096)
		select {
		case <-s.closeConn[connId]:
			break loop
		default:
			_, err := conn.Read(buffer)
			if err == io.EOF {
				return
			} else if err != nil {
				log.Println(err)
				break loop
			}
			fType, resp, err := s.handleMsg(buffer[:], sessionKey, conn, connId)
			if err != nil {
				log.Println(err)
				if fType != CLOSE {
					fType, resp, err = createErrCloseFrameHandshake(err)
					if err != nil {
						log.Printf("error when trying to prepare a close error message: %v", err)
						break loop
					}
				}
			}
			_, err = conn.Write(resp)
			if err != nil {
				log.Println(err)
				break loop
			} else if fType == CLOSE {
				break loop
			}
		}
	}
	conn.Close()
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
