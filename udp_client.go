package canoe

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
)

type (
	UDPClient struct {
		sessionKey []byte
	}
	PacketListItem struct {
		EncryptedPacket []byte
		OrderNumber     uint32
	}
)

// fletcher64 implements the Fletcher checksum algorithm
// Data is split into 64bit words
func fletcher64(data []byte) uint64 {
	var sum1, sum2 uint64
	const mod = 0xFFFFFFFFFFFF
	for _, b := range data {
		sum1 = (sum1 + uint64(b)) % mod
		sum2 = (sum2 + sum1) % mod
	}
	return (sum2 << 32) | sum1
}

// createPackets will open a file, separate it into packets, compress the packets, encrypt them and order them
// UDP packets can be at most 65507 bytes, IP header is 20 bytes, UDP header is 8 bytes
// Order number is 4 bytes and the checksum is 8 bytes
func (u *UDPClient) createPackets(pathToFile string, maxPacketSize int) ([]PacketListItem, error) {
	var packets []PacketListItem
	dataSize := (maxPacketSize - 4 - 8 - maxPacketSize%8) / 8 // To maximimze efficiency when computing the checksum, we make sure that dataSize is evenly divisible by 8 (64 bits = 8 bytes)
	// open the File
	file, err := os.Open(pathToFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	gzB := make([]byte, dataSize-28)                 // the encrypted data will always be 28 bytes longer
	b := make([]byte, int(float64(dataSize-28)/0.7)) // gzip compression can sometimes hit 70% efficiency so we make a buffer that big
	gzBuf := bytes.NewBuffer(gzB)
	gz := gzip.NewWriter(gzBuf)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	var seq uint32 = 1
	for {
		// Read some data from the file
		bytesRead, err := file.Read(b)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		// compress it, hopefully filling our bytes.Buffer
		_, err = gz.Write(b[:bytesRead])
		if err != nil {
			return nil, err
		}
		err = gz.Flush()
		if err != nil {
			return nil, err
		}
		// Create a new packet
		newPacket := Packet{
			OrderNumber: seq,
			Data:        gzBuf.Bytes(),
		}
		// Compute the checksum
		newPacket.Checksum = fletcher64(newPacket.Data[:])
		// encrypt the packet
		encryptedPacket, err := EncryptAESGCM(newPacket.Serialize(), u.sessionKey)
		if err != nil {
			return nil, err
		}
		packets = append(packets, PacketListItem{EncryptedPacket: encryptedPacket[:], OrderNumber: seq})
		seq += 1
	}
	return packets, nil
}
