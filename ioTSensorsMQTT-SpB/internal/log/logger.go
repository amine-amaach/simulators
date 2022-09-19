package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

func NewLogger(
	level, format string,
	disableTimestamp bool,
) *logrus.Logger {
	var log = logrus.New()

	switch format {
	case "JSON":
		log.Formatter = new(logrus.JSONFormatter)
		log.Formatter.(*logrus.JSONFormatter).DisableTimestamp = disableTimestamp
	default:
		log.Formatter = new(logrus.TextFormatter)
		log.Formatter.(*logrus.TextFormatter).DisableColors = false
		log.Formatter.(*logrus.TextFormatter).DisableTimestamp = disableTimestamp
	}

	switch level {
	case "ERROR":
		log.Level = logrus.ErrorLevel
	case "TRACE":
		log.Level = logrus.TraceLevel
	case "DEBUG":
		log.Level = logrus.DebugLevel
	case "FATAL":
		log.Level = logrus.FatalLevel
	case "WARN":
		log.Level = logrus.WarnLevel
	default:
		log.Level = logrus.InfoLevel

	}

	log.Out = os.Stdout
	return log
}
