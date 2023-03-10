package canoe

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	bg "github.com/SSSOCPaulCote/blunderguard"
)

const (
	ErrInvalidChecksum = bg.Error("invalid checksum")
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
	PACKET_ACK
)

type StatusTypes uint8

const (
	OK StatusTypes = iota
	ERROR
)

type TCPMsg interface {
	Serialize() []byte
}

// What is sent over the wire TCP
type Frame struct {
	Type    MsgTypes `json:"type"`    // Indicator for msg receiver
	Payload string   `json:"payload"` // Encrypted and base64 encoded
}

func (f Frame) Serialize() []byte {
	b, _ := json.Marshal(f)
	return b[:]
}

type HandshakeInit struct {
	Version      uint8  `json:"version"`       // Protocol version
	HandshakeKey []byte `json:"handshake_key"` // Client generated, symmetric key encrypted with servers pubkey
	Payload      []byte `json:"payload"`       // Clients pubkey encrypted with handshake key
	Signature    []byte `json:"signature"`     // Client signs the serialized and hashed version of this message with their private key
}

func (h HandshakeInit) Serialize() []byte {
	b, _ := json.Marshal(h)
	return b[:]
}

func (h HandshakeInit) String() string {
	return fmt.Sprintf("Version=%v\nHandshakeKey=%s\nPayload=%s", h.Version, h.HandshakeKey, h.Payload)
}

func (h HandshakeInit) serializeForSign() []byte {
	var hBytes []byte
	hBytes = append(hBytes, []byte(fmt.Sprintf("{\"version\":%v,\"handshake_key\":", h.Version))...)
	hBytes = append(hBytes, h.HandshakeKey...)
	hBytes = append(hBytes, []byte(",\"payload\":")...)
	hBytes = append(hBytes, h.Payload...)
	hBytes = append(hBytes, '}')
	return hBytes[:]
}

func (h HandshakeInit) Sign(privateKey *rsa.PrivateKey, rand io.Reader) ([]byte, error) {
	hBytes := h.serializeForSign()
	hashedBytes := sha256.Sum256(hBytes)
	sig, err := rsa.SignPSS(rand, privateKey, crypto.SHA256, hashedBytes[:], nil)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

type AckFrame struct {
	Status  StatusTypes `json:"status"`  // OK or ERROR
	Payload []byte      `json:"payload"` // The specific ACK JSON object serialized if OK or an error message
}

func (a AckFrame) Serialize() []byte {
	b, _ := json.Marshal(a)
	return b[:]
}

func (a AckFrame) String() string {
	return fmt.Sprintf("Status=%v\nPayload=%s", a.Status, a.Payload)
}

// Message is encrypted with handshake key
type HandshakeAck struct {
	SessionKey []byte `json:"session_key"` // Server generated, symmetric key encrypted with client pubkey
	Signature  []byte `json:"signature"`   // Server signs the serialized and hashed version of this message with their private key
}

func (h HandshakeAck) Serialize() []byte {
	b, _ := json.Marshal(h)
	return b[:]
}

func (h HandshakeAck) String() string {
	return fmt.Sprintf("SessionKey=%s\nSignature=%s", h.SessionKey, h.Signature)
}

func (h HandshakeAck) serializeForSign() []byte {
	var hBytes []byte
	hBytes = append(hBytes, []byte("{\"session_key\":")...)
	hBytes = append(hBytes, h.SessionKey...)
	hBytes = append(hBytes, '}')
	return hBytes[:]
}

func (h HandshakeAck) Sign(privateKey *rsa.PrivateKey, rand io.Reader) ([]byte, error) {
	hBytes := h.serializeForSign()
	hashedBytes := sha256.Sum256(hBytes)
	sig, err := rsa.SignPSS(rand, privateKey, crypto.SHA256, hashedBytes[:], nil)
	if err != nil {
		return nil, err
	}
	return sig[:], nil
}

type TransferTypes uint8

const (
	PUT_FILE TransferTypes = iota // Can support other TransferTypes in the future
)

type TransferFrame struct {
	Type    TransferTypes `json:"transfer_type"` // determines transfer type so server can properly handle the message
	Payload []byte        `json:"payload"`       // metadata about the particular transfer type
}

func (t TransferFrame) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

func (t TransferFrame) String() string {
	return fmt.Sprintf("Type=%v\nPayload=%s", t.Type, t.Payload)
}

// encrypted with session key
type PutFileTransferInit struct {
	FileSize        uint64 `json:"file_size"`         // bytes
	FileName        string `json:"file_name"`         // filename.ext
	NumberOfPackets uint32 `json:"number_of_packets"` // total number of packets to be transfered
}

func (t PutFileTransferInit) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

func (t PutFileTransferInit) String() string {
	return fmt.Sprintf("FileSize=%v\nFileName=%s\nNumberOfPackets=%v", t.FileSize, t.FileName, t.NumberOfPackets)
}

// encrypted with session key
type TransferAck struct {
	UDPPort uint16 `json:"udp_port"` // Port that the server will listen on for UDP traffic
}

func (t TransferAck) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

// Packet encrypted with session key, sent over UDP
type Packet struct {
	OrderNumber uint32
	Data        []byte
	Checksum    uint64
}

func (p Packet) Serialize() []byte {
	var b []byte
	orderBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(orderBytes, p.OrderNumber)
	b = append(b, orderBytes...)
	checksumBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(checksumBytes, p.Checksum)
	b = append(b, checksumBytes...)
	b = append(b, p.Data...)
	return b[:]
}

// DecryptPacket will take an encrypted packet, decrypt it and parse it
func DecryptPacket(p []byte, key []byte) (Packet, error) {
	decryptedPacket, err := DecryptAESGCM(p, key)
	if err != nil {
		return Packet{}, err
	}
	// ensure the checksum is intact
	checksum := binary.LittleEndian.Uint64(decryptedPacket[4:16])
	if checksum != fletcher64(decryptedPacket[16:]) {
		return Packet{}, ErrInvalidChecksum
	}
	gz, err := gzip.NewReader(bytes.NewBuffer(decryptedPacket[16:]))
	if err != nil {
		return Packet{}, err
	}
	decompressed := make([]byte, int(float64(len(decryptedPacket[16:]))/0.7))
	bytesRead, err := gz.Read(decompressed)
	if err != nil {
		return Packet{}, err
	}
	data := decompressed[:bytesRead]
	return Packet{
		OrderNumber: binary.LittleEndian.Uint32(decryptedPacket[:4]),
		Data:        data[:],
		Checksum:    checksum,
	}, nil
}

// Encrypted with session key
type TransferComplete struct {
	PacketsToResend []uint32 `json:"packets_to_resend"` // array is empty if transfer is successful
}

func (t TransferComplete) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

// Encrypted with session key
type TransferCompleteAck struct{}

func (t TransferCompleteAck) Serialize() []byte {
	return []byte(`"completed"`)
}

// Encrypted with session key
type Close struct{}

func (c Close) Serialize() []byte {
	return []byte(`"close"`)
}

// Encrypted with session key
type Ping struct{}

func (p Ping) Serialize() []byte {
	return []byte(`"ping"`)
}

// Encrypted with session key
type Pong struct{}

func (p Pong) Serialize() []byte {
	return []byte(`"pong"`)
}

type PacketAck struct {
	OrderNumber uint32 `json:"order_numbers"`
}

func (a PacketAck) Serialize() []byte {
	b, _ := json.Marshal(a)
	return b[:]
}
