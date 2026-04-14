package dtls

import "time"

type handshakeTimer interface {
	Stop() bool
}

type handshakeClock interface {
	Now() time.Time
	AfterFunc(d time.Duration, fn func()) handshakeTimer
}

type realHandshakeClock struct{}

func (realHandshakeClock) Now() time.Time {
	return time.Now()
}

func (realHandshakeClock) AfterFunc(d time.Duration, fn func()) handshakeTimer {
	return &realHandshakeTimer{timer: time.AfterFunc(d, fn)}
}

type realHandshakeTimer struct {
	timer *time.Timer
}

func (t *realHandshakeTimer) Stop() bool {
	if t == nil || t.timer == nil {
		return false
	}
	return t.timer.Stop()
}
