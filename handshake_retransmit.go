package dtls

import (
	"time"
)

var handshakeRetransmitIntervals = []time.Duration{
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	60 * time.Second,
}

const handshakeFinalFlightRetention = 2 * time.Minute

type handshakeFlightTrigger uint8

const (
	handshakeFlightTriggerNone handshakeFlightTrigger = iota
	handshakeFlightTriggerClientHelloInitial
	handshakeFlightTriggerClientHelloCookie
	handshakeFlightTriggerClientFinal
)

type handshakeFlight struct {
	trigger      handshakeFlightTrigger
	packets      [][]byte
	nextDelayIdx int
	timer        handshakeTimer
	expiresAt    time.Time
	generation   uint64
}

type handshakeFlightCapture struct {
	trigger handshakeFlightTrigger
	packets [][]byte
}

func (t handshakeFlightTrigger) String() string {
	switch t {
	case handshakeFlightTriggerClientHelloInitial:
		return "clienthello-initial"
	case handshakeFlightTriggerClientHelloCookie:
		return "clienthello-cookie"
	case handshakeFlightTriggerClientFinal:
		return "client-final"
	default:
		return "none"
	}
}

func (s *session) now() time.Time {
	if s != nil && s.listener != nil && s.listener.clock != nil {
		return s.listener.clock.Now()
	}
	return time.Now()
}

func (s *session) getHandshakeClock() handshakeClock {
	if s != nil && s.listener != nil && s.listener.clock != nil {
		return s.listener.clock
	}
	return realHandshakeClock{}
}

func cloneFlightPackets(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, packet := range packets {
		out[i] = append([]byte(nil), packet...)
	}
	return out
}

func (s *session) beginFlightCapture(trigger handshakeFlightTrigger) {
	if s == nil || s.handshake == nil {
		return
	}
	s.handshake.retransmitMu.Lock()
	s.handshake.flightCapture = &handshakeFlightCapture{trigger: trigger}
	s.handshake.retransmitMu.Unlock()
}

func (s *session) abortFlightCapture() {
	if s == nil || s.handshake == nil {
		return
	}
	s.handshake.retransmitMu.Lock()
	s.handshake.flightCapture = nil
	s.handshake.retransmitMu.Unlock()
}

func (s *session) captureFlightPacket(packet []byte) {
	if s == nil || s.handshake == nil {
		return
	}
	s.handshake.retransmitMu.Lock()
	if s.handshake.flightCapture != nil {
		s.handshake.flightCapture.packets = append(s.handshake.flightCapture.packets, append([]byte(nil), packet...))
	}
	s.handshake.retransmitMu.Unlock()
}

func (s *session) sendCapturedFlight(trigger handshakeFlightTrigger, expectResponse bool, retain bool, send func() error) error {
	s.beginFlightCapture(trigger)
	err := send()
	if err != nil {
		s.abortFlightCapture()
		return err
	}
	s.finishFlightCapture(expectResponse, retain)
	return nil
}

func (s *session) stopActiveFlightLocked() {
	if s.handshake.activeFlight != nil && s.handshake.activeFlight.timer != nil {
		s.handshake.activeFlight.timer.Stop()
	}
	s.handshake.activeFlight = nil
}

func (s *session) clearRetainedFinalFlightLocked(now time.Time) {
	if s.handshake.retainedFinalFlight != nil && !s.handshake.retainedFinalFlight.expiresAt.IsZero() && !now.Before(s.handshake.retainedFinalFlight.expiresAt) {
		s.handshake.retainedFinalFlight = nil
	}
}

func (s *session) finishFlightCapture(expectResponse bool, retain bool) {
	if s == nil || s.handshake == nil {
		return
	}

	now := s.now()
	s.handshake.retransmitMu.Lock()
	capture := s.handshake.flightCapture
	s.handshake.flightCapture = nil
	if capture == nil || len(capture.packets) == 0 {
		s.handshake.retransmitMu.Unlock()
		return
	}

	if expectResponse {
		s.stopActiveFlightLocked()
		s.handshake.flightGeneration++
		flight := &handshakeFlight{
			trigger:    capture.trigger,
			packets:    cloneFlightPackets(capture.packets),
			generation: s.handshake.flightGeneration,
		}
		s.handshake.activeFlight = flight
		s.scheduleNextFlightTimerLocked(flight)
		s.handshake.retransmitMu.Unlock()
		logDebug(s.peer, nil, "stored server flight for %s retransmit", capture.trigger.String())
		return
	}

	if retain {
		s.handshake.retainedFinalFlight = &handshakeFlight{
			trigger:   capture.trigger,
			packets:   cloneFlightPackets(capture.packets),
			expiresAt: now.Add(handshakeFinalFlightRetention),
		}
		s.handshake.retransmitMu.Unlock()
		logDebug(s.peer, nil, "retained server final flight for %s", handshakeFinalFlightRetention.String())
		return
	}

	s.handshake.retransmitMu.Unlock()
}

func (s *session) scheduleNextFlightTimerLocked(flight *handshakeFlight) {
	if flight == nil || flight.nextDelayIdx >= len(handshakeRetransmitIntervals) {
		if flight != nil {
			flight.timer = nil
		}
		return
	}
	delay := handshakeRetransmitIntervals[flight.nextDelayIdx]
	generation := flight.generation
	flight.timer = s.getHandshakeClock().AfterFunc(delay, func() {
		s.handleFlightTimer(generation)
	})
}

func (s *session) handleFlightTimer(generation uint64) {
	if s == nil || s.handshake == nil {
		return
	}

	var packets [][]byte
	var trigger handshakeFlightTrigger
	var attempt int

	s.handshake.retransmitMu.Lock()
	flight := s.handshake.activeFlight
	if flight == nil || flight.generation != generation {
		s.handshake.retransmitMu.Unlock()
		return
	}

	packets = cloneFlightPackets(flight.packets)
	trigger = flight.trigger
	attempt = flight.nextDelayIdx + 1
	flight.nextDelayIdx++
	s.scheduleNextFlightTimerLocked(flight)
	s.handshake.retransmitMu.Unlock()

	if err := s.writeStoredFlightPackets(packets); err != nil {
		logWarn(s.peer, nil, err, "handshake timer retransmit write")
		return
	}
	logDebug(s.peer, nil, "timer retransmit attempt %d for %s", attempt, trigger.String())
}

func (s *session) writeStoredFlightPackets(packets [][]byte) error {
	for _, packet := range packets {
		if err := s.peer.transport.WritePacket(append([]byte(nil), packet...)); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) replayStoredFlight(trigger handshakeFlightTrigger, reason string) bool {
	if s == nil || s.handshake == nil {
		return false
	}

	now := s.now()
	var packets [][]byte

	s.handshake.retransmitMu.Lock()
	s.clearRetainedFinalFlightLocked(now)
	switch {
	case s.handshake.activeFlight != nil && s.handshake.activeFlight.trigger == trigger:
		packets = cloneFlightPackets(s.handshake.activeFlight.packets)
	case trigger == handshakeFlightTriggerClientFinal && s.handshake.retainedFinalFlight != nil:
		packets = cloneFlightPackets(s.handshake.retainedFinalFlight.packets)
	}
	s.handshake.retransmitMu.Unlock()

	if len(packets) == 0 {
		return false
	}
	if err := s.writeStoredFlightPackets(packets); err != nil {
		logWarn(s.peer, nil, err, "handshake replay write")
		return true
	}
	logDebug(s.peer, nil, "replayed %s server flight for %s", trigger.String(), reason)
	return true
}

func (s *session) promoteActiveFlightToRetainedFinal() {
	if s == nil || s.handshake == nil {
		return
	}
	now := s.now()

	s.handshake.retransmitMu.Lock()
	flight := s.handshake.activeFlight
	if flight == nil || flight.trigger != handshakeFlightTriggerClientFinal {
		s.handshake.retransmitMu.Unlock()
		return
	}
	if flight.timer != nil {
		flight.timer.Stop()
	}
	s.handshake.retainedFinalFlight = &handshakeFlight{
		trigger:   handshakeFlightTriggerClientFinal,
		packets:   cloneFlightPackets(flight.packets),
		expiresAt: now.Add(handshakeFinalFlightRetention),
	}
	s.handshake.activeFlight = nil
	s.handshake.retransmitMu.Unlock()
}

func (s *session) clearRetainedFinalIfExpired() {
	if s == nil || s.handshake == nil {
		return
	}
	s.handshake.retransmitMu.Lock()
	s.clearRetainedFinalFlightLocked(s.now())
	s.handshake.retransmitMu.Unlock()
}

func (s *session) noteClientFlightProgress(trigger handshakeFlightTrigger) {
	if s == nil || s.handshake == nil {
		return
	}

	now := s.now()
	s.handshake.retransmitMu.Lock()
	s.clearRetainedFinalFlightLocked(now)

	if trigger == handshakeFlightTriggerClientHelloInitial || trigger == handshakeFlightTriggerClientHelloCookie {
		s.handshake.retainedFinalFlight = nil
	}

	if s.handshake.activeFlight != nil {
		switch trigger {
		case handshakeFlightTriggerClientHelloCookie:
			if s.handshake.activeFlight.trigger == handshakeFlightTriggerClientHelloInitial {
				s.stopActiveFlightLocked()
			}
		case handshakeFlightTriggerClientFinal:
			if s.handshake.activeFlight.trigger != handshakeFlightTriggerClientFinal {
				s.stopActiveFlightLocked()
			}
		}
	}
	s.handshake.retransmitMu.Unlock()
}

func (s *session) stopHandshakeFlights() {
	if s == nil || s.handshake == nil {
		return
	}
	s.handshake.retransmitMu.Lock()
	if s.handshake.activeFlight != nil && s.handshake.activeFlight.timer != nil {
		s.handshake.activeFlight.timer.Stop()
	}
	s.handshake.activeFlight = nil
	s.handshake.retainedFinalFlight = nil
	s.handshake.flightCapture = nil
	s.handshake.retransmitMu.Unlock()
}

func (s *session) duplicateTriggerForHandshake(hs *handshake) handshakeFlightTrigger {
	if hs == nil {
		return handshakeFlightTriggerNone
	}

	switch hs.Header.HandshakeType {
	case handshakeType_ClientHello:
		if hs.ClientHello != nil && !hs.ClientHello.HasCookie() {
			return handshakeFlightTriggerClientHelloInitial
		}
		return handshakeFlightTriggerClientHelloCookie
	case handshakeType_ClientKeyExchange, handshakeType_Finished:
		return handshakeFlightTriggerClientFinal
	default:
		return handshakeFlightTriggerNone
	}
}

func (s *session) handleDuplicateHandshake(rec *record, hs *handshake) {
	if s == nil || s.Type != SessionType_Server || hs == nil {
		return
	}

	trigger := s.duplicateTriggerForHandshake(hs)
	if trigger == handshakeFlightTriggerNone {
		logDebug(s.peer, rec, "duplicate handshake received seq: %d", hs.Header.Sequence)
		return
	}

	if s.listener.dropDuplicateHandshakes || DropDuplicateHandshakes {
		logDebug(s.peer, rec, "received duplicate handshake, ignoring")
		return
	}

	if !s.replayStoredFlight(trigger, hs.Print()) {
		logDebug(s.peer, rec, "duplicate handshake received seq: %d (no cached flight)", hs.Header.Sequence)
	}
}

func (s *session) handleDuplicateChangeCipherSpec(rec *record) {
	if s == nil || s.Type != SessionType_Server {
		return
	}
	if s.listener.dropDuplicateHandshakes || DropDuplicateHandshakes {
		logDebug(s.peer, rec, "received duplicate change cipher spec, ignoring")
		return
	}
	if !s.replayStoredFlight(handshakeFlightTriggerClientFinal, "duplicate change cipher spec") {
		logDebug(s.peer, rec, "duplicate change cipher spec received (no cached flight)")
	}
}
