package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fatih/color"
)

var (
	customLogger = log.New(os.Stdout, "", 0)
	globalLogger *Logger
	loggerOnce   sync.Once
)

func formatTimestamp(t time.Time) string {
	t = t.Local()
	base := t.Format("2006-01-02 15-04-05")
	ms := t.Nanosecond() / 1_000_000
	return fmt.Sprintf("%s-%03d", base, ms)
}

func getFormattedTime() string {
	return formatTimestamp(time.Now())
}

// Colors
var (
	ColorRed    = color.New(color.FgRed)
	ColorGreen  = color.New(color.FgGreen)
	ColorYellow = color.New(color.FgYellow)
	ColorBlue   = color.New(color.FgBlue)
)

type LogLevel string

const (
	Debug   LogLevel = "DEBUG"
	Info    LogLevel = "INFO"
	Warning LogLevel = "WARNING"
	Error   LogLevel = "ERROR"
)

type ErrorInfo struct {
	Message string `json:"message"`
}

// JSONL entry (one object per line)
type LogEntry struct {
	Timestamp  string     `json:"timestamp"`
	Level      LogLevel   `json:"level"`
	TaskNumber int        `json:"task_number,omitempty"`
	Name       string     `json:"name,omitempty"` // function name
	Message    string     `json:"message"`
	Error      *ErrorInfo `json:"error,omitempty"`
}

type Logger struct {
	logsDir     string
	consoleOnly bool

	mu   sync.Mutex
	file *os.File // single JSONL file (append-only)
}

func InitLogger(logsDir string, consoleOnly bool) error {
	var err error
	loggerOnce.Do(func() {
		globalLogger = &Logger{
			logsDir:     logsDir,
			consoleOnly: consoleOnly,
		}

		if consoleOnly {
			return
		}

		if err = os.MkdirAll(logsDir, 0755); err != nil {
			err = fmt.Errorf("failed to create logs directory: %w", err)
			return
		}

		path := filepath.Join(logsDir, "app.jsonl")
		globalLogger.file, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			err = fmt.Errorf("open log file: %w", err)
			return
		}
	})
	return err
}

func CloseLogger() {
	if globalLogger == nil {
		return
	}
	globalLogger.mu.Lock()
	defer globalLogger.mu.Unlock()

	if globalLogger.file != nil {
		_ = globalLogger.file.Close()
		globalLogger.file = nil
	}
}

func (l *Logger) log(level LogLevel, c *color.Color, taskNumber int, name, message string, err error) {
	entry := LogEntry{
		Timestamp:  formatTimestamp(time.Now()),
		Level:      level,
		TaskNumber: taskNumber,
		Name:       name,
		Message:    message,
	}
	if err != nil {
		entry.Error = &ErrorInfo{Message: err.Error()}
	}

	taskPart := "-"
	if taskNumber >= 0 {
		taskPart = fmt.Sprintf("%d", taskNumber)
	}
	namePart := name
	if namePart == "" {
		namePart = "-"
	}

	consoleMsg := fmt.Sprintf("%s [%s] [%s] %s", level, taskPart, namePart, message)
	if err != nil {
		consoleMsg += fmt.Sprintf(" | err=%v", err)
	}
	ColorfulLog(c, consoleMsg)

	if l.consoleOnly || l.file == nil {
		return
	}

	// JSONL append (serialized)
	l.mu.Lock()
	defer l.mu.Unlock()

	enc := json.NewEncoder(l.file)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(entry)
}

// Public API (only these four)
func LogDebug(taskNumber int, name, message string) {
	if globalLogger != nil {
		globalLogger.log(Debug, ColorBlue, taskNumber, name, message, nil)
	}
}

func LogInfo(taskNumber int, name, message string) {
	if globalLogger != nil {
		globalLogger.log(Info, ColorGreen, taskNumber, name, message, nil)
	}
}

func LogWarning(taskNumber int, name, message string) {
	if globalLogger != nil {
		globalLogger.log(Warning, ColorYellow, taskNumber, name, message, nil)
	}
}

func LogError(taskNumber int, name, message string, err error) {
	if globalLogger != nil {
		globalLogger.log(Error, ColorRed, taskNumber, name, message, err)
	}
}

func ColorfulLog(c *color.Color, message string) {
	coloredMessage := c.Sprintf("[%s] %s", getFormattedTime(), message)
	customLogger.Println(coloredMessage)
}
