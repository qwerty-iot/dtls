// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtls

import (
	"crypto/x509"
	"encoding/hex"
	"sync"
	"time"
)

type sessionCacheEntry struct {
	Id           []byte    `json:"id"`
	Identity     []byte    `json:"identity"`
	Expires      time.Time `json:"expires"`
	PublicKey    []byte    `json:"publicKey"`
	cert         *x509.Certificate
	CertEncoded  []byte      `json:"cert"`
	EccCurve     eccCurve    `json:"eccCurve"`
	EccKeypair   *eccKeypair `json:"eccKeypair"`
	MasterSecret []byte      `json:"masterSecret"`
}

func (sce *sessionCacheEntry) Marshal() []byte {
	//tbd
	return nil
}

var sessionCache = map[string]sessionCacheEntry{}
var sessionCacheMux sync.Mutex
var sessionCacheSweepTime time.Time

// set to whatever you want the cache time to live to be
var SessionCacheTtl = time.Hour * 24

// set to the interval to look for expired sessions
var SessionCacheSweepInterval = time.Minute * -5

func SessionCacheSize() int {
	sessionCacheMux.Lock()
	size := len(sessionCache)
	sessionCacheMux.Unlock()
	return size
}

func getFromSessionCache(sessionId string) *sessionCacheEntry {
	sessionCacheMux.Lock()
	sce, found := sessionCache[sessionId]
	sessionCacheMux.Unlock()
	if !found {
		return nil
	}
	return &sce
}

func saveToSessionCache(s *session) {
	now := time.Now()
	sessionCacheMux.Lock()
	sessionCache[hex.EncodeToString(s.Id)] = sessionCacheEntry{
		Identity:     s.peerIdentity,
		MasterSecret: s.handshake.masterSecret,
		PublicKey:    s.peerPublicKey,
		cert:         s.peerCert,
		EccCurve:     s.handshake.eccCurve,
		EccKeypair:   s.handshake.eccKeypair,
		Expires:      now.Add(SessionCacheTtl),
	}
	sessionCacheMux.Unlock()

	//after entries are added, check to see if we need to sweep out old sessions.
	if sessionCacheSweepTime.Before(now.Add(SessionCacheSweepInterval)) {
		go sessionCacheSweep()
		sessionCacheSweepTime = now
	}
}

func sessionCacheSweep() {
	now := time.Now()
	sessionCacheMux.Lock()
	for sessionId, sce := range sessionCache {
		if sce.Expires.Before(now) {
			delete(sessionCache, sessionId)
		}
	}
	sessionCacheMux.Unlock()
}
