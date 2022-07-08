package utils

import (
	"fmt"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Instantiate a zap logger.
func NewLogger() *zap.SugaredLogger {
	consoleEncoderCfg := zap.NewProductionEncoderConfig()
	consoleEncoderCfg.EncodeTime = zapcore.TimeEncoderOfLayout("01/02/2006 15:04:05")
	consoleEncoderCfg.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderCfg)
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, os.Stderr, zapcore.ErrorLevel),
		zapcore.NewCore(consoleEncoder, os.Stderr, zapcore.FatalLevel),
		zapcore.NewCore(consoleEncoder, os.Stdout, zapcore.InfoLevel),
	)
	l := zap.New(core)
	return l.Sugar()
}

// Foreground colors.
const (
	Black uint8 = iota + 30
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

// Colorize colorizes a string by a given color.
func Colorize(s string, c uint8) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", c, s)
}
