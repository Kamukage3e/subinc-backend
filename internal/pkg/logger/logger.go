package logger

import (
	"context"

	"os"
	"github.com/spf13/viper"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Field is an alias for zap.Field for convenience
type Field = zap.Field

// Level is an alias for zapcore.Level
type Level = zapcore.Level

// Logger is a structured logger for capturing info, warning, debug, and error events
type Logger struct {
	zap        *zap.Logger
	level      Level
	fields     []Field
	ctxFields  []string
	sampleRate int
}

// Use custom type for context keys to avoid collisions in context.WithValue only
type contextKey string

// Log levels
const (
	// DebugLevel has verbose message
	DebugLevel = zapcore.DebugLevel
	// InfoLevel is default log level
	InfoLevel = zapcore.InfoLevel
	// WarnLevel is for logging messages about possible issues
	WarnLevel = zapcore.WarnLevel
	// ErrorLevel is for logging errors
	ErrorLevel = zapcore.ErrorLevel
	// FatalLevel logs a message, then calls os.Exit(1)
	FatalLevel = zapcore.FatalLevel

	// TraceIDKey is the key used for the trace ID in logs
	TraceIDKey = "trace_id"
	// TenantIDKey is the key used for the tenant ID in logs
	TenantIDKey = "tenant_id"
	// UserIDKey is the key used for the user ID in logs
	UserIDKey = "user_id"
	// ServiceKey is the key used for the service name in logs
	ServiceKey = "service"
	// HostKey is the key used for the host name in logs
	HostKey = "host"
	// EnvKey is the key used for the environment in logs
	EnvKey = "env"
)

// Field constructors
var (
	// String constructs a field with the given key and value
	String = zap.String
	// Strings constructs a field with the given key and []string value
	Strings = zap.Strings
	// Int constructs a field with the given key and value
	Int = zap.Int
	// Float64 constructs a field with the given key and value
	Float64 = zap.Float64
	// Bool constructs a field with the given key and value
	Bool = zap.Bool
	// ErrorField constructs a field with the given key and error
	ErrorField = zap.Error
	// Duration constructs a field with the given key and value
	Duration = zap.Duration
	// Time constructs a field with the given key and value
	Time = zap.Time
	// Any constructs a field with the given key and any value
	Any = zap.Any
)

// Default is a default logger instance (console, colorful)
var Default *Logger

func init() {
	Default = NewProduction()
}

// With adds a variadic number of fields to the logging context
func (l *Logger) With(fields ...Field) *Logger {
	return &Logger{
		zap:        l.zap.With(fields...),
		level:      l.level,
		fields:     append(l.fields, fields...),
		ctxFields:  l.ctxFields,
		sampleRate: l.sampleRate,
	}
}

// WithContext adds context values to the logger
func (l *Logger) WithContext(ctx context.Context) *Logger {
	if ctx == nil {
		return l
	}

	fields := make([]Field, 0, len(l.ctxFields))
	for _, key := range l.ctxFields {
		if value := ctx.Value(key); value != nil {
			fields = append(fields, String(key, value.(string)))
		}
	}

	if len(fields) == 0 {
		return l
	}

	return &Logger{
		zap:        l.zap.With(fields...),
		level:      l.level,
		fields:     append(l.fields, fields...),
		ctxFields:  l.ctxFields,
		sampleRate: l.sampleRate,
	}
}

// Debug logs a message at Debug level
func (l *Logger) Debug(msg string, fields ...Field) {
	l.zap.Debug(msg, fields...)
}

// Info logs a message at Info level
func (l *Logger) Info(msg string, fields ...Field) {
	l.zap.Info(msg, fields...)
}

// Warn logs a message at Warn level
func (l *Logger) Warn(msg string, fields ...Field) {
	l.zap.Warn(msg, fields...)
}

// Error logs a message at Error level
func (l *Logger) Error(msg string, fields ...Field) {
	l.zap.Error(msg, fields...)
}

// Fatal logs a message at Fatal level and then calls os.Exit(1)
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.zap.Fatal(msg, fields...)
}

// Flush flushes any buffered log entries
func (l *Logger) Flush() error {
	return l.zap.Sync()
}

// getEnv gets an environment variable or returns a default
func getEnv(key, defaultValue string) string {
	if value := viper.GetString(key); value != "" {
		return value
	}
	return defaultValue
}

// NewProduction returns a production-grade, colorful, human-friendly logger for all environments
func NewProduction() *Logger {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder // Colorize level
	config.EncodeCaller = zapcore.ShortCallerEncoder
	config.EncodeName = zapcore.FullNameEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(config)
	core := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapcore.InfoLevel)
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return &Logger{zap: zapLogger, level: InfoLevel}
}

// NewDev returns a fully colorful, human-friendly logger for local/dev
func NewDev() *Logger {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder // Colorize level
	config.EncodeCaller = zapcore.ShortCallerEncoder
	config.EncodeName = zapcore.FullNameEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(config)
	core := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapcore.DebugLevel)
	zapLogger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	return &Logger{zap: zapLogger, level: DebugLevel}
}

// NewNoop returns a no-op logger (for tests or when logging is not needed)
func NewNoop() *Logger {
	config := zap.NewDevelopmentEncoderConfig()
	config.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncodeLevel = zapcore.CapitalColorLevelEncoder
	consoleEncoder := zapcore.NewConsoleEncoder(config)
	core := zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapcore.ErrorLevel)
	zapLogger := zap.New(core)
	return &Logger{zap: zapLogger, level: ErrorLevel}
}

// ContextWithValues adds values to a context that will be picked up by WithContext
func ContextWithValues(ctx context.Context, keyvals ...string) context.Context {
	if len(keyvals)%2 != 0 {
		return ctx
	}

	for i := 0; i < len(keyvals); i += 2 {
		ctx = context.WithValue(ctx, contextKey(keyvals[i]), keyvals[i+1])
	}

	return ctx
}

// ContextWithTenant adds tenant ID to context
func ContextWithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, contextKey(TenantIDKey), tenantID)
}

// ContextWithTraceID adds trace ID to context
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKey(TraceIDKey), traceID)
}

// ContextWithUserID adds user ID to context
func ContextWithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, contextKey(UserIDKey), userID)
}

// LogDebug logs a message at Debug level using the default logger
func LogDebug(msg string, fields ...Field) {
	Default.Debug(msg, fields...)
}

// LogInfo logs a message at Info level using the default logger
func LogInfo(msg string, fields ...Field) {
	Default.Info(msg, fields...)
}

// LogWarn logs a message at Warn level using the default logger
func LogWarn(msg string, fields ...Field) {
	Default.Warn(msg, fields...)
}

// LogError logs a message at Error level using the default logger
func LogError(msg string, fields ...Field) {
	Default.Error(msg, fields...)
}

// LogFatal logs a message at Fatal level using the default logger
func LogFatal(msg string, fields ...Field) {
	Default.Fatal(msg, fields...)
}

// WithFields returns a new logger with the given fields using the default logger
func WithFields(fields ...Field) *Logger {
	return Default.With(fields...)
}

// WithCtx returns a new logger with values from the given context using the default logger
func WithCtx(ctx context.Context) *Logger {
	return Default.WithContext(ctx)
}

// FlushLogs flushes any buffered log entries for the default logger
func FlushLogs() error {
	return Default.Flush()
}
