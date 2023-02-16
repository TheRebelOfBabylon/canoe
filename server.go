package canoe

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"sync"

	bg "github.com/SSSOCPaulCote/blunderguard"
	"github.com/google/uuid"
)

const (
	ErrVersionMismatch = bg.Error("protocol version mismatch")
)

var (
	defaultVersion uint8 = 0
)

type ServerConfig struct {
	PrivateKey *rsa.PrivateKey
	Rand       io.Reader
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

func (s *Server) handleResponse(resp TCPMsg) (TCPMsg, error) {
	switch r := resp.(type) {
	case HandshakeInit:
		// check version compatibility

	}
}

// parseBytes will parse the bytes received via TCP into a useable format
func (s *Server) parseBytes(b []byte, key []byte) (TCPMsg, error) {
	var f Frame
	err := json.Unmarshal(b, &f)
	if err != nil {
		return nil, err
	}
	// base64 decode Payload
	pay, err := base64.StdEncoding.DecodeString(f.Payload)
	if err != nil {
		return nil, err
	}
	switch f.Type {
	case HANDSHAKE_INIT:
		// check for version compatibility
		resp := &HandshakeInit{}
		err = json.Unmarshal(pay, &resp)
		if err != nil {
			return nil, err
		}
		if resp.Version != s.Version {
			return nil, ErrVersionMismatch
		}
		// decrypt handshake_key with pubkey
		// decrypt payload with handshake_key

		// create session key
		// encrypt session key with client pubkey
		// make HandshakeAck message and serialize
		// Encrypt
		// Encode
	case HANDSHAKE_ACK:
		// decrypt first
		resp = HandshakeAck{}
	case TRANSFER_INIT:
		resp = TransferInit{}
	case TRANSFER_ACK:
		resp = TransferAck{}
	case COMPLETE:
		resp = TransferComplete{}
	case COMPLETE_ACK:
		resp = TransferCompleteAck{}
	}

	return resp, nil
}

// handleConnection is run as a go routine for every new connection
func (s *Server) handleConnection(conn net.Conn, connId string) {
	defer func() {
		conn.Close()
		close(s.closeConn[connId])
		s.wg.Done()
	}()
	buffer := make([]byte, 1024)
	for {
		select {
		case <-s.closeConn[connId]:
			return
		default:
			_, err := conn.Read(buffer)
			if err != nil {
				log.Println(err)
			}
			resp, err := parseBytes(buffer[:])
			if err != nil {
				log.Println(err)
			}
			step += 1
			if step == COMPLETE_ACK {
				return
			}
			req, err := s.handleResponse(resp)
			if err != nil {
				log.Println(err)
			}
			_, err = conn.Write(req.Serialize())
			if err != nil {
				log.Println(err)
			}
			step += 1
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
	if s.tcpLis != nil {
		return s.tcpLis.Close()
	}
	return nil
}
