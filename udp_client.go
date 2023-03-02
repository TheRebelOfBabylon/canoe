package canoe

import (
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

var (
	dataSize = 1456
)

type (
	UDPClient struct {
		sessionKey []byte
		conn       *net.UDPConn
	}
	PacketQueueItem struct {
		EncryptedPacket []byte
		Acked           bool
		TimeSent        time.Time
	}
	PacketQueue struct {
		Queue []PacketQueueItem
		sync.RWMutex
	}
)

// Ack changes the Acked status of a packet to true
func (q *PacketQueue) Ack(orderNumber int) {
	q.Lock()
	defer q.Unlock()
	q.Queue[orderNumber].Acked = true
}

// IsAck determines if a given packet was acked by the server
func (q *PacketQueue) IsAck(orderNumber int) bool {
	q.RLock()
	defer q.RUnlock()
	return q.Queue[orderNumber].Acked
}

// CanSend determines if a given packet has timed out and if it hasn't already been acked by the server
func (q *PacketQueue) CanSend(orderNumber int, timeout time.Duration) bool {
	q.RLock()
	defer q.RUnlock()
	return time.Now().After(q.Queue[orderNumber].TimeSent.Add(timeout)) && !q.Queue[orderNumber].Acked
}

// TimeSent updates the TimeSent parameter for a given packet
func (q *PacketQueue) TimeSent(orderNumber int, timeSent time.Time) {
	q.Lock()
	defer q.Unlock()
	q.Queue[orderNumber].TimeSent = timeSent
}

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

//NewUDPClient will initialize the UDP client
func NewUDPClient(host string, key []byte) (*UDPClient, error) {
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	return &UDPClient{
		sessionKey: key[:],
		conn:       conn,
	}, nil
}

// createPackets will open a file, separate it into packets, compress the packets, encrypt them and order them
// Typical NIC MTU is 1500 Bytes, IP header is 20 bytes, UDP header is 8 bytes
// Order number is 4 bytes and the checksum is 8 bytes
// We want our data to be a multiple of 8 since that is most efficient with our checksum algorithm
// dataSize is therefore 1456 bytes
func createPackets(pathToFile string, sessionKey []byte) (*PacketQueue, error) {
	var packets []PacketQueueItem
	// open the File
	file, err := os.Open(pathToFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	gzB := make([]byte, dataSize)                 // the encrypted data will always be 28 bytes longer
	b := make([]byte, int(float64(dataSize)/0.7)) // gzip compression can sometimes hit 70% efficiency so we make a buffer that big
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
		encryptedPacket, err := EncryptAESGCM(newPacket.Serialize(), sessionKey)
		if err != nil {
			return nil, err
		}
		packets = append(packets, PacketQueueItem{EncryptedPacket: encryptedPacket[:]})
		seq += 1
	}
	return &PacketQueue{
		Queue: packets,
	}, nil
}

// Close will properly close the UDP client connection
func (c *UDPClient) Close() error {
	return c.conn.Close()
}

// Buffer creates a new appropriately sized buffer
func (c *UDPClient) Buffer() []byte {
	return make([]byte, dataSize)
}
