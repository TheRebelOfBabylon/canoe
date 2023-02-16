package canoe

import "encoding/json"

type TCPMsg interface {
	Serialize() []byte
}

type HandshakeInit struct {
	Version      uint8  `json:"version"`       // Protocol version
	HandshakeKey []byte `json:"handshake_key"` // Client generated, symmetric key encrypted with servers pubkey (Base64+Hex)
	Payload      []byte `json:"payload"`       // Clients pubkey encrypted with handshake key (Base64+Hex)
}

func (h HandshakeInit) Serialize() []byte {
	b, _ := json.Marshal(h)
	return b[:]
}

// Message is encrypted with handshake key
type HandshakeAck struct {
	SessionKey []byte `json:"session_key"` // Server generated, symmetric key encrypted with client pubkey
	UDPPort    uint16 `json:"udp_port"`    // Port that the server will listen on for UDP traffic
}

func (h HandshakeAck) Serialize() []byte {
	b, _ := json.Marshal(h)
	return b[:]
}

// encrypted with session key
type TransferInit struct {
	FileSize        uint64 `json:"file_size"`         // bytes
	FileName        string `json:"file_name"`         // filename.ext
	NumberOfPackets uint32 `json:"number_of_packets"` // Files are broken down into 1024 byte sized packets
}

func (t TransferInit) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

// encrypted with session key
type TransferAck struct {
	Status uint8  `json:"status"` // OK or ERR
	Msg    string `json:"msg"`    // error message if
}

func (t TransferAck) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

// Packet encrypted with session key, sent over UDP
type Packet struct {
	OrderNumber uint32
	Data        []byte
}

type TransferComplete struct {
	PacketsToResend []uint32 `json:"packets_to_resend"` // array is empty if transfer is successful
}

func (t TransferComplete) Serialize() []byte {
	b, _ := json.Marshal(t)
	return b[:]
}

type TransferCompleteAck struct{}

func (t TransferCompleteAck) Serialize() []byte {
	return []byte(`{ "completed": "ok" }`)
}
