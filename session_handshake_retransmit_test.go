package dtls

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeHandshakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeHandshakeTimer
}

type fakeHandshakeTimer struct {
	clock   *fakeHandshakeClock
	when    time.Time
	fn      func()
	stopped bool
}

func newFakeHandshakeClock(start time.Time) *fakeHandshakeClock {
	return &fakeHandshakeClock{now: start}
}

func (c *fakeHandshakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeHandshakeClock) AfterFunc(d time.Duration, fn func()) handshakeTimer {
	c.mu.Lock()
	defer c.mu.Unlock()

	timer := &fakeHandshakeTimer{
		clock: c,
		when:  c.now.Add(d),
		fn:    fn,
	}
	c.timers = append(c.timers, timer)
	return timer
}

func (c *fakeHandshakeClock) Advance(d time.Duration) {
	target := c.Now().Add(d)

	for {
		var timer *fakeHandshakeTimer

		c.mu.Lock()
		for _, candidate := range c.timers {
			if candidate.stopped {
				continue
			}
			if candidate.when.After(target) {
				continue
			}
			if timer == nil || candidate.when.Before(timer.when) {
				timer = candidate
			}
		}
		if timer == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		c.now = timer.when
		timer.stopped = true
		c.mu.Unlock()

		timer.fn()
	}
}

func (t *fakeHandshakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()

	if t.stopped {
		return false
	}
	t.stopped = true
	return true
}

type testHandshakeEndpoint struct {
	addr    string
	mu      sync.Mutex
	writes  [][]byte
	pending int
}

func (e *testHandshakeEndpoint) String() string {
	return e.addr
}

func (e *testHandshakeEndpoint) WritePacket(data []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.writes = append(e.writes, append([]byte(nil), data...))
	return nil
}

func (e *testHandshakeEndpoint) AllWrites() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	return cloneFlightPackets(e.writes)
}

func (e *testHandshakeEndpoint) DrainPending() [][]byte {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.pending >= len(e.writes) {
		return nil
	}
	packets := cloneFlightPackets(e.writes[e.pending:])
	e.pending = len(e.writes)
	return packets
}

func (e *testHandshakeEndpoint) WriteCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.writes)
}

func newTestHandshakeListener(clock handshakeClock) *Listener {
	return &Listener{
		peers:              make(map[string]*Peer),
		readQueue:          make(chan *msg, 8),
		cipherSuites:       []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8},
		compressionMethods: []CompressionMethod{CompressionMethod_Null},
		maxPacketSize:      1400,
		maxHandshakeSize:   1200,
		clock:              clock,
	}
}

func newTestHandshakeSession(listener *Listener, sessionType string, addr string) (*session, *testHandshakeEndpoint) {
	endpoint := &testHandshakeEndpoint{addr: addr}
	peer := &Peer{transport: endpoint, activity: listener.clock.Now(), transportQueue: make(chan []byte, 8)}

	var sess *session
	if sessionType == SessionType_Client {
		sess = newClientSession(peer)
		sess.peerIdentity = []byte("myid")
	} else {
		sess = newServerSession(peer)
	}

	sess.listener = listener
	peer.session = sess

	return sess, endpoint
}

func newTestClientHelloRecord(t *testing.T, random []byte, cookie []byte, seq uint16) *record {
	t.Helper()

	hs := newHandshake(handshakeType_ClientHello)
	require.NoError(t, hs.ClientHello.Init(nil, random, cookie, []CipherSuite{CipherSuite_TLS_PSK_WITH_AES_128_CCM_8}, []CompressionMethod{CompressionMethod_Null}))
	hs.Header.Sequence = seq

	return newRecord(ContentType_Handshake, 0, uint64(seq), nil, hs.Bytes())
}

func deliverHandshakePacket(t *testing.T, sess *session, packet []byte) {
	t.Helper()

	data := packet
	for len(data) > 0 {
		rec, rem, err := sess.parseRecord(data)
		require.NoError(t, err)
		require.NotNil(t, rec)
		require.True(t, rec.IsHandshake(), "expected handshake record")
		require.NoError(t, sess.processHandshakePacket(rec))
		data = rem
	}
}

func pumpHandshakeTraffic(t *testing.T, client *session, clientEndpoint *testHandshakeEndpoint, server *session, serverEndpoint *testHandshakeEndpoint) {
	t.Helper()

	for i := 0; i < 32; i++ {
		progressed := false

		for _, packet := range clientEndpoint.DrainPending() {
			progressed = true
			deliverHandshakePacket(t, server, packet)
		}
		for _, packet := range serverEndpoint.DrainPending() {
			progressed = true
			deliverHandshakePacket(t, client, packet)
		}

		if client.isHandshakeDone() && server.isHandshakeDone() && !progressed {
			return
		}
		if !progressed {
			break
		}
	}

	require.True(t, client.isHandshakeDone(), "client handshake did not complete")
	require.True(t, server.isHandshakeDone(), "server handshake did not complete")
}

func testRandom(seed byte) []byte {
	random := make([]byte, 32)
	for i := range random {
		random[i] = seed + byte(i)
	}
	return random
}

func TestServerRetransmitsHelloVerifyRequestForDuplicatesAndTimers(t *testing.T) {
	clock := newFakeHandshakeClock(time.Unix(0, 0))
	listener := newTestHandshakeListener(clock)
	server, serverEndpoint := newTestHandshakeSession(listener, SessionType_Server, "server")

	random := testRandom(0x10)
	initialClientHello := newTestClientHelloRecord(t, random, nil, 0)

	require.NoError(t, server.processHandshakePacket(initialClientHello))
	require.Len(t, serverEndpoint.AllWrites(), 1)
	helloVerify := serverEndpoint.AllWrites()[0]

	require.NoError(t, server.processHandshakePacket(newTestClientHelloRecord(t, random, nil, 0)))
	require.Len(t, serverEndpoint.AllWrites(), 2)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[1])

	clock.Advance(3 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 2)

	clock.Advance(1 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 3)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[2])

	clock.Advance(7 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 3)

	clock.Advance(1 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 4)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[3])

	clock.Advance(16 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 5)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[4])

	clock.Advance(32 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 6)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[5])

	clock.Advance(60 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 7)
	assert.Equal(t, helloVerify, serverEndpoint.AllWrites()[6])

	clock.Advance(60 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 7)
}

func TestServerReplaysCookieHelloFlightAndRetiresPreviousTimer(t *testing.T) {
	clock := newFakeHandshakeClock(time.Unix(0, 0))
	listener := newTestHandshakeListener(clock)
	server, serverEndpoint := newTestHandshakeSession(listener, SessionType_Server, "server")

	random := testRandom(0x20)

	require.NoError(t, server.processHandshakePacket(newTestClientHelloRecord(t, random, nil, 0)))
	helloVerify := serverEndpoint.AllWrites()[0]
	cookie := append([]byte(nil), server.handshake.cookie...)

	require.NoError(t, server.processHandshakePacket(newTestClientHelloRecord(t, random, cookie, 1)))
	require.Len(t, serverEndpoint.AllWrites(), 2)
	serverHelloFlight := serverEndpoint.AllWrites()[1]

	require.NoError(t, server.processHandshakePacket(newTestClientHelloRecord(t, random, cookie, 1)))
	require.Len(t, serverEndpoint.AllWrites(), 3)
	assert.Equal(t, serverHelloFlight, serverEndpoint.AllWrites()[2])

	clock.Advance(4 * time.Second)
	require.Len(t, serverEndpoint.AllWrites(), 4)
	assert.Equal(t, serverHelloFlight, serverEndpoint.AllWrites()[3])
	assert.NotEqual(t, helloVerify, serverEndpoint.AllWrites()[3])
}

func TestServerRetainsAndReplaysFinalFlightForTwoMinutes(t *testing.T) {
	clock := newFakeHandshakeClock(time.Unix(0, 0))
	serverListener := newTestHandshakeListener(clock)
	clientListener := newTestHandshakeListener(clock)

	mks := NewKeystoreInMemory()
	psk, err := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	require.NoError(t, err)
	mks.AddKey([]byte("myid"), psk)
	SetKeyStores([]Keystore{mks})

	server, serverEndpoint := newTestHandshakeSession(serverListener, SessionType_Server, "server")
	client, clientEndpoint := newTestHandshakeSession(clientListener, SessionType_Client, "client")

	require.NoError(t, client.startHandshake())
	pumpHandshakeTraffic(t, client, clientEndpoint, server, serverEndpoint)

	require.True(t, server.isHandshakeDone())
	require.True(t, client.isHandshakeDone())
	require.NotNil(t, server.handshake.retainedFinalFlight)

	serverWrites := serverEndpoint.AllWrites()
	require.GreaterOrEqual(t, len(serverWrites), 4)
	originalFinalFlight := cloneFlightPackets(serverWrites[len(serverWrites)-2:])

	clientWrites := clientEndpoint.AllWrites()
	require.GreaterOrEqual(t, len(clientWrites), 5)
	duplicateFinished := clientWrites[len(clientWrites)-1]

	seq0 := server.sequenceNumber0
	seq1 := server.sequenceNumber1

	deliverHandshakePacket(t, server, duplicateFinished)
	serverWrites = serverEndpoint.AllWrites()
	require.Len(t, serverWrites, 6)
	assert.Equal(t, originalFinalFlight[0], serverWrites[4])
	assert.Equal(t, originalFinalFlight[1], serverWrites[5])
	assert.Equal(t, seq0, server.sequenceNumber0)
	assert.Equal(t, seq1, server.sequenceNumber1)

	clock.Advance((2 * time.Minute) - time.Second)
	deliverHandshakePacket(t, server, duplicateFinished)
	serverWrites = serverEndpoint.AllWrites()
	require.Len(t, serverWrites, 8)
	assert.Equal(t, originalFinalFlight[0], serverWrites[6])
	assert.Equal(t, originalFinalFlight[1], serverWrites[7])

	clock.Advance(2 * time.Second)
	deliverHandshakePacket(t, server, duplicateFinished)
	require.Len(t, serverEndpoint.AllWrites(), 8)
}

func TestNewClientHelloAfterCompletionResetsHandshakeState(t *testing.T) {
	clock := newFakeHandshakeClock(time.Unix(0, 0))
	serverListener := newTestHandshakeListener(clock)
	clientListener := newTestHandshakeListener(clock)

	mks := NewKeystoreInMemory()
	psk, err := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	require.NoError(t, err)
	mks.AddKey([]byte("myid"), psk)
	SetKeyStores([]Keystore{mks})

	server, serverEndpoint := newTestHandshakeSession(serverListener, SessionType_Server, "server")
	client, clientEndpoint := newTestHandshakeSession(clientListener, SessionType_Client, "client")

	require.NoError(t, client.startHandshake())
	pumpHandshakeTraffic(t, client, clientEndpoint, server, serverEndpoint)

	require.True(t, server.isHandshakeDone())
	require.NotNil(t, server.handshake.retainedFinalFlight)

	before := serverEndpoint.WriteCount()
	deliverHandshakePacket(t, server, newTestClientHelloRecord(t, testRandom(0x90), nil, 0).Bytes())

	require.Equal(t, before+1, serverEndpoint.WriteCount())
	require.Equal(t, "recv-clienthello-initial", server.handshake.state)
	require.Nil(t, server.handshake.retainedFinalFlight)
	require.NotNil(t, server.handshake.activeFlight)
	require.Equal(t, handshakeFlightTriggerClientHelloInitial, server.handshake.activeFlight.trigger)
}
