package dtls

import (
	"sync"
	"time"
)

type sessionCacheEntry struct {
	id       []byte
	len      int
	identity string
	expires  time.Time
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

func getIdentityFromCache(sessionId string) string {
	var identity string
	sessionCacheMux.Lock()
	sce, found := sessionCache[sessionId]
	if found {
		identity = sce.identity
	}
	sessionCacheMux.Unlock()
	return identity
}

func setIdentityToCache(sessionId string, identity string) {
	now := time.Now()
	sessionCacheMux.Lock()
	sessionCache[sessionId] = sessionCacheEntry{identity: identity, expires: now.Add(SessionCacheTtl)}
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
		if sce.expires.Before(now) {
			delete(sessionCache, sessionId)
		}
	}
	sessionCacheMux.Unlock()
}
