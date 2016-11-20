package dtls

import (
	"fmt"
	"log"
	"time"
)

const (
	LogLevelError string = "error"
	LogLevelWarn  string = "warn"
	LogLevelInfo  string = "info"
	LogLevelDebug string = "debug"
)

type LogFunc func(ts time.Time, level string, msg string)

var logFunc LogFunc = defaultLogFunc
var logLevel int = 0

func SetLogLevel(level string) {
	switch level {
	case LogLevelError:
		logLevel = 1
	case LogLevelWarn:
		logLevel = 2
	case LogLevelInfo:
		logLevel = 3
	case LogLevelDebug:
		logLevel = 4
	default:
		logLevel = 0
	}
}

func defaultLogFunc(ts time.Time, level string, msg string) {
	log.Printf(" [" + level + "] " + msg)
}

func logError(f string, args ...interface{}) {
	if logLevel < 1 {
		return
	}
	logFunc(time.Now(), LogLevelError, fmt.Sprintf(f, args...))
}

func logWarn(f string, args ...interface{}) {
	if logLevel < 2 {
		return
	}
	logFunc(time.Now(), LogLevelWarn, fmt.Sprintf(f, args...))
}

func logInfo(f string, args ...interface{}) {
	if logLevel < 3 {
		return
	}
	logFunc(time.Now(), LogLevelInfo, fmt.Sprintf(f, args...))
}

func logDebug(f string, args ...interface{}) {
	if logLevel < 4 {
		return
	}
	logFunc(time.Now(), LogLevelDebug, fmt.Sprintf(f, args...))
}
