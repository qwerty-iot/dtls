package common

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

func defaultLogFunc(ts time.Time, level string, msg string) {
	log.Printf(" [" + level + "] " + msg)
}

func LogError(f string, args ...interface{}) {
	logFunc(time.Now(), LogLevelError, fmt.Sprintf(f, args...))
}

func LogWarn(f string, args ...interface{}) {
	logFunc(time.Now(), LogLevelWarn, fmt.Sprintf(f, args...))
}

func LogInfo(f string, args ...interface{}) {
	logFunc(time.Now(), LogLevelInfo, fmt.Sprintf(f, args...))
}

func LogDebug(f string, args ...interface{}) {
	logFunc(time.Now(), LogLevelDebug, fmt.Sprintf(f, args...))
}
