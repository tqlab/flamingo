package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Logger interface {
	Trace(f string, args ...interface{})
	Debug(f string, args ...interface{})
	Info(f string, args ...interface{})
	Warn(f string, args ...interface{})
	Error(f string, args ...interface{})
}

// NullLogger - An empty logger that ignores everything
type NullLogger struct{}

// Trace - no-op
func (l NullLogger) Trace(f string, args ...interface{}) {}

// Debug - no-op
func (l NullLogger) Debug(f string, args ...interface{}) {}

// Info - no-op
func (l NullLogger) Info(f string, args ...interface{}) {}

// Warn - no-op
func (l NullLogger) Warn(f string, args ...interface{}) {}

func (l NullLogger) Error(f string, args ...interface{}) {}

// ColorLogger - A Logger that logs to stdout in color
type ColorLogger struct {
}

// Trace - Log a very verbose trace message
func (l ColorLogger) Trace(f string, args ...interface{}) {
	l.output("blue", f, args...)
}

// Debug - Log a debug message
func (l ColorLogger) Debug(f string, args ...interface{}) {
	l.output("green", f, args...)
}

// Info - Log a general message
func (l ColorLogger) Info(f string, args ...interface{}) {
	l.output("default", f, args...)
}

// Warn - Log a warning
func (l ColorLogger) Warn(f string, args ...interface{}) {
	l.output("yellow", f, args...)
}

func (l ColorLogger) Error(f string, args ...interface{}) {
	l.output("red", f, args...)
}

func (l ColorLogger) output(color, f string, args ...interface{}) {

	date := time.Now().Format("2006-01-02 15:04:05.000")
	var format string
	switch color {
	case "blue":
		{
			format = "%s \033[34;4m%s\033[0m\n"
		}
	case "green":
		{
			format = "%s \033[32;4m%s\033[0m\n"
		}
	case "yellow":
		{
			format = "%s \033[33;4m%s\033[0m\n"
		}
	case "red":
		{
			format = "%s \033[31;4m%s\033[0m\n"
		}
	case "purple":
		{
			format = "%s \033[35;4m%s\033[0m\n"
		}
	case "darkgreen":
		{
			format = "%s \033[36;4m%s\033[0m\n"
		}

	default:
		format = "%s %s\n"

	}
	fmt.Printf(fmt.Sprintf(format, date, f), args...)
}

type FileLogger struct {
	logFile      *os.File
	errorLogFile *os.File
}

func NewFileLogger(logFileName, errorLogFileName string) *FileLogger {

	basicPath0 := filepath.Dir(logFileName)
	if _, err := os.Stat(basicPath0); os.IsNotExist(err) {
		os.MkdirAll(basicPath0, os.ModePerm)
	}

	basicPath1 := filepath.Dir(errorLogFileName)
	if _, err := os.Stat(basicPath1); os.IsNotExist(err) {
		os.MkdirAll(basicPath1, os.ModePerm)
	}

	var logFile *os.File
	if !checkFileIsExist(logFileName) {
		logFile, _ = os.Create(logFileName)
	} else {
		logFile, _ = os.OpenFile(logFileName, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	}

	var errorLogFile *os.File
	if !checkFileIsExist(errorLogFileName) {
		errorLogFile, _ = os.Create(errorLogFileName)
	} else {
		errorLogFile, _ = os.OpenFile(errorLogFileName, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	}

	return &FileLogger{
		logFile:      logFile,
		errorLogFile: errorLogFile,
	}
}

// Trace - no-op
func (fileLogger FileLogger) Trace(f string, args ...interface{}) {
	fileLogger.output(fileLogger.logFile, "blue", f, args...)
}

// Debug - no-op
func (fileLogger FileLogger) Debug(f string, args ...interface{}) {
	fileLogger.output(fileLogger.logFile, "green", f, args...)
}

// Info - no-op
func (fileLogger FileLogger) Info(f string, args ...interface{}) {
	fileLogger.output(fileLogger.logFile, "default", f, args...)
}

// Warn - no-op
func (fileLogger FileLogger) Warn(f string, args ...interface{}) {
	fileLogger.output(fileLogger.logFile, "yellow", f, args...)
}

func (fileLogger FileLogger) Error(f string, args ...interface{}) {
	fileLogger.output(fileLogger.errorLogFile, "red", f, args...)
}

func (fileLogger FileLogger) output(logFile *os.File, color, f string, args ...interface{}) {

	date := time.Now().Format("2006-01-02 15:04:05.000")
	var format string
	switch color {
	case "blue":
		{
			format = "%s \033[34;4m%s\033[0m\n"
		}
	case "green":
		{
			format = "%s \033[32;4m%s\033[0m\n"
		}
	case "yellow":
		{
			format = "%s \033[33;4m%s\033[0m\n"
		}
	case "red":
		{
			format = "%s \033[31;4m%s\033[0m\n"
		}
	case "purple":
		{
			format = "%s \033[35;4m%s\033[0m\n"
		}
	case "darkgreen":
		{
			format = "%s \033[36;4m%s\033[0m\n"
		}

	default:
		format = "%s %s\n"

	}

	newFormat := fmt.Sprintf(format, date, f)
	fileLogger.checkLogFile()
	line := fmt.Sprintf(newFormat, args...)
	logFile.Write([]byte(line))
	logFile.Sync()
}

func (fileLogger FileLogger) checkLogFile() {
	fileName := fileLogger.logFile.Name()
	errorFileName := fileLogger.errorLogFile.Name()
	info, err := os.Stat(fileName)
	if err != nil {
		return
	}

	y0, m0, d0 := info.ModTime().Date()
	y1, m1, d1 := time.Now().Date()
	if y0 < y1 || m0 < m1 || d0 < d1 {
		postfix := "." + strconv.Itoa(y0) + "-" + fmt.Sprintf("%02d", int(m0)) + "-" + fmt.Sprintf("%02d", d0)
		newFileName := fileName + postfix
		newErrorFileName := errorFileName + postfix
		os.Rename(fileName, newFileName)
		os.Rename(errorFileName, newErrorFileName)

		// close old file
		fileLogger.logFile.Close()
		fileLogger.errorLogFile.Close()

		// create new file
		fileLogger.logFile, _ = os.Create(fileName)
		fileLogger.errorLogFile, _ = os.Create(errorFileName)
	}
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}
