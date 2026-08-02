package dtls

import "time"

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

type handshakeFlightRecord struct {
	contentType ContentType
	epoch       uint16
	cid         []byte
	data        []byte
}

type handshakeFlightPacket struct {
	records []handshakeFlightRecord
}

type handshakeFlight struct {
	trigger      handshakeFlightTrigger
	packets      []handshakeFlightPacket
	nextDelayIdx int
	timer        handshakeTimer
	expiresAt    time.Time
	generation   uint64
}

type handshakeFlightCapture struct {
	trigger handshakeFlightTrigger
	packets []handshakeFlightPacket
}

type pendingHandshakeReplay struct {
	trigger             handshakeFlightTrigger
	reason              string
	firstRecordSequence *uint64
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

// cloneFlightPackets is used by the in-memory test transport as well as other
// callers that need an independent copy of raw datagrams.
func cloneFlightPackets(packets [][]byte) [][]byte {
	out := make([][]byte, len(packets))
	for i, packet := range packets {
		out[i] = append([]byte(nil), packet...)
	}
	return out
}

func cloneHandshakeFlightPackets(packets []handshakeFlightPacket) []handshakeFlightPacket {
	out := make([]handshakeFlightPacket, len(packets))
	for packetIdx, packet := range packets {
		out[packetIdx].records = make([]handshakeFlightRecord, len(packet.records))
		for recordIdx, record := range packet.records {
			out[packetIdx].records[recordIdx] = handshakeFlightRecord{
				contentType: record.contentType,
				epoch:       record.epoch,
				cid:         append([]byte(nil), record.cid...),
				data:        append([]byte(nil), record.data...),
			}
		}
	}
	return out
}

func cloneRecordForFlight(rec *record) handshakeFlightRecord {
	return handshakeFlightRecord{
		contentType: rec.ContentType,
		epoch:       rec.Epoch,
		cid:         append([]byte(nil), rec.Cid...),
		data:        append([]byte(nil), rec.Data...),
	}
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

func (s *session) captureFlightRecords(records []*record) {
	if s == nil || s.handshake == nil || len(records) == 0 {
		return
	}
	packet := handshakeFlightPacket{records: make([]handshakeFlightRecord, len(records))}
	for i, rec := range records {
		packet.records[i] = cloneRecordForFlight(rec)
	}

	s.handshake.retransmitMu.Lock()
	if s.handshake.flightCapture != nil {
		s.handshake.flightCapture.packets = append(s.handshake.flightCapture.packets, packet)
	}
	s.handshake.retransmitMu.Unlock()
}

func (s *session) sendCapturedFlight(trigger handshakeFlightTrigger, expectResponse bool, retain bool, send func() error) error {
	s.beginFlightCapture(trigger)
	s.flightWriteMu.Lock()
	err := send()
	s.flightWriteMu.Unlock()
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
			packets:    cloneHandshakeFlightPackets(capture.packets),
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
			packets:   cloneHandshakeFlightPackets(capture.packets),
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

	var packets []handshakeFlightPacket
	var trigger handshakeFlightTrigger
	var attempt int

	s.handshake.retransmitMu.Lock()
	flight := s.handshake.activeFlight
	if flight == nil || flight.generation != generation {
		s.handshake.retransmitMu.Unlock()
		return
	}

	packets = cloneHandshakeFlightPackets(flight.packets)
	trigger = flight.trigger
	attempt = flight.nextDelayIdx + 1
	flight.nextDelayIdx++
	s.scheduleNextFlightTimerLocked(flight)
	s.handshake.retransmitMu.Unlock()

	if err := s.writeStoredFlightPackets(packets, nil); err != nil {
		logWarn(s.peer, nil, err, "handshake timer retransmit write")
		return
	}
	logDebug(s.peer, nil, "timer retransmit attempt %d for %s", attempt, trigger.String())
}

func (s *session) writeStoredFlightPackets(packets []handshakeFlightPacket, firstRecordSequence *uint64) error {
	s.flightWriteMu.Lock()
	defer s.flightWriteMu.Unlock()

	firstRecord := true
	for _, packet := range packets {
		records := make([]*record, 0, len(packet.records))
		for _, stored := range packet.records {
			var requestedSequence *uint64
			if firstRecord && firstRecordSequence != nil {
				requestedSequence = firstRecordSequence
			}
			sequence := s.getRecordSequence(stored.epoch, requestedSequence)
			firstRecord = false
			records = append(records, newRecord(stored.contentType, stored.epoch, sequence, append([]byte(nil), stored.cid...), append([]byte(nil), stored.data...)))
		}

		if len(records) == 1 {
			if err := s.writeRecord(records[0]); err != nil {
				return err
			}
			continue
		}
		if err := s.writeRecords(records); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) replayStoredFlight(trigger handshakeFlightTrigger, reason string, firstRecordSequence *uint64) bool {
	if s == nil || s.handshake == nil {
		return false
	}

	now := s.now()
	var packets []handshakeFlightPacket

	s.handshake.retransmitMu.Lock()
	s.clearRetainedFinalFlightLocked(now)
	switch {
	case s.handshake.activeFlight != nil && s.handshake.activeFlight.trigger == trigger:
		packets = cloneHandshakeFlightPackets(s.handshake.activeFlight.packets)
	case trigger == handshakeFlightTriggerClientFinal && s.handshake.retainedFinalFlight != nil:
		packets = cloneHandshakeFlightPackets(s.handshake.retainedFinalFlight.packets)
	}
	s.handshake.retransmitMu.Unlock()

	if len(packets) == 0 {
		return false
	}
	if err := s.writeStoredFlightPackets(packets, firstRecordSequence); err != nil {
		logWarn(s.peer, nil, err, "handshake replay write")
		return true
	}
	logDebug(s.peer, nil, "replayed %s server flight for %s", trigger.String(), reason)
	return true
}

func cloneUint64(value *uint64) *uint64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func (s *session) beginHandshakeDatagram() {
	if s == nil {
		return
	}
	s.datagramReplayMu.Lock()
	s.deferFlightReplay = true
	s.pendingFlightReplay = nil
	s.datagramReplayMu.Unlock()
}

func (s *session) finishHandshakeDatagram() {
	if s == nil {
		return
	}
	s.datagramReplayMu.Lock()
	pending := s.pendingFlightReplay
	s.pendingFlightReplay = nil
	s.deferFlightReplay = false
	s.datagramReplayMu.Unlock()

	if pending != nil && !s.replayStoredFlight(pending.trigger, pending.reason, pending.firstRecordSequence) {
		logDebug(s.peer, nil, "duplicate handshake received (no cached %s flight)", pending.trigger.String())
	}
}

func (s *session) requestStoredFlightReplay(trigger handshakeFlightTrigger, reason string, firstRecordSequence *uint64) bool {
	if s == nil {
		return false
	}
	s.datagramReplayMu.Lock()
	if s.deferFlightReplay {
		if s.pendingFlightReplay == nil || trigger >= s.pendingFlightReplay.trigger {
			s.pendingFlightReplay = &pendingHandshakeReplay{
				trigger:             trigger,
				reason:              reason,
				firstRecordSequence: cloneUint64(firstRecordSequence),
			}
		}
		s.datagramReplayMu.Unlock()
		return true
	}
	s.datagramReplayMu.Unlock()
	return s.replayStoredFlight(trigger, reason, firstRecordSequence)
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
		packets:   cloneHandshakeFlightPackets(flight.packets),
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

	var firstRecordSequence *uint64
	if trigger == handshakeFlightTriggerClientHelloInitial {
		firstRecordSequence = &rec.Sequence
	}
	if !s.requestStoredFlightReplay(trigger, hs.Print(), firstRecordSequence) {
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
	if !s.requestStoredFlightReplay(handshakeFlightTriggerClientFinal, "duplicate change cipher spec", nil) {
		logDebug(s.peer, rec, "duplicate change cipher spec received (no cached flight)")
	}
}
