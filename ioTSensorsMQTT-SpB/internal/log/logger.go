package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

func NewLogger() *logrus.Logger{
	var log = logrus.New()
	log.Formatter = new(logrus.TextFormatter)                     //default
	log.Formatter.(*logrus.TextFormatter).DisableColors = false    // remove colors
	log.Formatter.(*logrus.TextFormatter).DisableTimestamp = false // remove timestamp from test output
	log.Level = logrus.InfoLevel
	log.Out = os.Stdout
	return log
}