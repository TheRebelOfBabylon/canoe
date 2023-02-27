package canoe

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	bg "github.com/SSSOCPaulCote/blunderguard"
	"github.com/google/uuid"
)

const (
	ErrAlreadySubscribed = bg.Error("already subscribed to the queue")
)

type (
	QueueListener struct {
		IsConnected bool
		Signal      chan int
	}
	ByteQueue struct {
		queue     [][]byte
		listeners map[string]*QueueListener
		sync.RWMutex
	}
	UDPServer struct {
		queue      *ByteQueue
		sessionkey []byte
		numPackets uint32
		conn       *net.UDPConn
		workingDir string
	}
)

// NewByteQueue instantiates a new ByteQueue struct
func NewByteQueue() *ByteQueue {
	return &ByteQueue{
		queue:     [][]byte{},
		listeners: make(map[string]*QueueListener),
	}
}

// Pop returns the first item in the queue and deletes it from the queue
func (q *ByteQueue) Pop() []byte {
	q.Lock()
	defer q.Unlock()
	var item []byte
	if len(q.queue) > 0 {
		item = q.queue[0]
		q.queue = q.queue[1:]
	} else {
		q.queue = [][]byte{}
	}
	return item
}

// Push adds a new item to the back of the queue
func (q *ByteQueue) Push(v []byte) {
	q.Lock()
	defer q.Unlock()
	q.queue = append(q.queue, v)
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

// Subscribe returns a channel which will have signals sent when a new item is pushed as well as an unsub function
func (q *ByteQueue) Subscribe(name string) (chan int, func(), error) {
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

// NewUDPServer instantiates a new UDPServer struct
func NewUDPServer(sessionKey []byte, numPackets uint32, workingDir string) *UDPServer {
	return &UDPServer{
		sessionkey: sessionKey,
		numPackets: numPackets,
		queue:      NewByteQueue(),
		workingDir: workingDir,
	}
}

// ListenAndServe will create a UDP listener on the given port and spin up
// a goroutine to handle incoming connections
func (u *UDPServer) ListenAndServe(port uint16, fileName string) error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	u.conn = conn
	go u.handleConnection(fileName)
	return nil
}

// handleConnection is the goroutine for handling incoming connections
func (u *UDPServer) handleConnection(fileName string) {
	quitChan := make(chan struct{})
	defer close(quitChan)
	go u.handlePackets(fileName, quitChan)
	for i := 0; i < int(u.numPackets); i++ {
		buffer := make([]byte, 4096)
		bytesRead, _, err := u.conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println(err)
			break
		}
		u.queue.Push(buffer[:bytesRead])
	}
}

// handlePackets is the goroutine which will read packets from a queue
// unpack them and write them to the file
func (u *UDPServer) handlePackets(fileName string, quit chan struct{}) {
	file, err := os.Create(filepath.Join(u.workingDir, fileName))
	if err != nil {
		fmt.Println(err)
		return
	}
	sigChan, unsub, err := u.queue.Subscribe(uuid.NewString())
	if err != nil {
		// TODO - should push errors to a channel for use in the main server loops
		fmt.Println(err)
		return
	}
	defer unsub()
	for {
		select {
		case i := <-sigChan:
			if i != 0 {
				unencryptedPacket, err := DecryptAESGCM(u.queue.Pop(), u.sessionkey)
				if err != nil {
					fmt.Println(err)
					return
				}
				_, err = file.Write(unencryptedPacket)
				if err != nil {
					fmt.Println(err)
					return
				}
			}
		case <-quit:
			return
		}
	}
}

// Close will close the underlying UDP connection
func (u *UDPServer) Close() error {
	return u.conn.Close()
}
