package canoe

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type MsgTypes uint8

const (
	HANDSHAKE_INIT MsgTypes = iota
	HANDSHAKE_ACK
	TRANSFER_INIT
	TRANSFER_ACK
	COMPLETE
	COMPLETE_ACK
	CLOSE
	PING
	PONG
)

type StatusTypes uint8

const (
	OK StatusTypes = iota
	ERROR
)

type TCPMsg interface {
	Serialize() string
}

// What is sent over the wire TCP
type Frame struct {
	Type    MsgTypes `json:"type"`    // Indicator for msg receiver
	Payload string   `json:"payload"` // The base 64 encoded msg
}

func (f Frame) Serialize() []byte {
	b, _ := json.Marshal(f)
	return b
}

type HandshakeInit struct {
	Version      uint8  `json:"version"`       // Protocol version
	HandshakeKey string `json:"handshake_key"` // Client generated, symmetric key encrypted with servers pubkey and hex encoded
	Payload      string `json:"payload"`       // Clients pubkey encrypted with handshake key and hex encoded
}

func (h HandshakeInit) Serialize() string {
	b, _ := json.Marshal(h)
	return base64.StdEncoding.EncodeToString(b)
}

func (h HandshakeInit) String() string {
	return fmt.Sprintf("Version=%v\nHandshakeKey=%s\nPayload=%s", h.Version, h.HandshakeKey, h.Payload)
}

// Message is encrypted with handshake key
type HandshakeAck struct {
	SessionKey string `json:"session_key"` // Server generated, symmetric key encrypted with client pubkey and hex encoded
	UDPPort    uint16 `json:"udp_port"`    // Port that the server will listen on for UDP traffic
}

func (h HandshakeAck) Serialize() string {
	b, _ := json.Marshal(h)
	return base64.StdEncoding.EncodeToString(b)
}

func (h HandshakeAck) String() string {
	return fmt.Sprintf("SessionKey=%s\nUDP Port=%v", h.SessionKey, h.UDPPort)
}

// encrypted with session key
type TransferInit struct {
	FileSize        uint64 `json:"file_size"`         // bytes
	FileName        string `json:"file_name"`         // filename.ext
	NumberOfPackets uint32 `json:"number_of_packets"` // Files are broken down into 1024 byte sized packets
}

func (t TransferInit) Serialize() string {
	b, _ := json.Marshal(t)
	return base64.StdEncoding.EncodeToString(b)
}

func (t TransferInit) String() string {
	return fmt.Sprintf("FileSize=%v\nFileName=%s\nNumberOfPackets=%v", t.FileSize, t.FileName, t.NumberOfPackets)
}

// encrypted with session key
type TransferAck struct {
	Status StatusTypes `json:"status"` // OK or ERR
	Msg    string      `json:"msg"`    // error message if
}

func (t TransferAck) Serialize() string {
	b, _ := json.Marshal(t)
	return base64.StdEncoding.EncodeToString(b)
}

func (t TransferAck) String() string {
	return fmt.Sprintf("Status=%v\nMsg=%s", t.Status, t.Msg)
}

// Packet encrypted with session key, sent over UDP
type Packet struct {
	OrderNumber uint32
	Data        string // base64 encoded data
}

// Encrypted with session key
type TransferComplete struct {
	PacketsToResend []uint32 `json:"packets_to_resend"` // array is empty if transfer is successful
}

func (t TransferComplete) Serialize() string {
	b, _ := json.Marshal(t)
	return base64.StdEncoding.EncodeToString(b)
}

// Encrypted with session key
type TransferCompleteAck struct{}

func (t TransferCompleteAck) Serialize() string {
	return base64.StdEncoding.EncodeToString([]byte(`{ "msg": "completed" }`))
}

// Encrypted with session key
type Close struct{}

func (c Close) Serialize() string {
	return base64.StdEncoding.EncodeToString([]byte(`{ "msg": "close" }`))
}

// Encrypted with session key
type Ping struct{}

func (p Ping) Serialize() string {
	return base64.StdEncoding.EncodeToString([]byte(`{ "msg": "ping" }`))
}

// Encrypted with session key
type Pong struct{}

func (p Pong) Serialize() string {
	return base64.StdEncoding.EncodeToString([]byte(`{ "msg": "pong" }`))
}
