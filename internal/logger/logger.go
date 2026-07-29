package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger 封装slog，支持debug文件输出
type Logger struct {
	*slog.Logger
	debugFile *os.File
	mu        sync.RWMutex
}

var (
	defaultLogger *Logger
	once          sync.Once
	// 主日志文件写入器（lumberjack 大小轮转：单文件 50MB，最多保留 2 个文件即当前+1备份，超出删最旧）
	fileWriter *lumberjack.Logger
)

// 初始化全局logger — 日志真实落地到 data/logs/arcway.log（同时保留 stdout 供 journalctl/容器查看）
func Init() *Logger {
	once.Do(func() {
		_ = os.MkdirAll("data/logs", 0755)
		fileWriter = &lumberjack.Logger{
			Filename:   "data/logs/arcway.log",
			MaxSize:    50, // MB
			MaxBackups: 1,  // 当前文件 + 1 个备份 = 最多 2 个文件
			MaxAge:     0,  // 不按时间删，只看大小/数量
			Compress:   false,
		}
		handler := newTextHandler(io.MultiWriter(os.Stdout, fileWriter), slog.LevelInfo)
		defaultLogger = &Logger{
			Logger: slog.New(handler),
		}
	})
	return defaultLogger
}

// 获取全局logger实例
func GetLogger() *Logger {
	if defaultLogger == nil {
		return Init()
	}
	return defaultLogger
}

// 创建自定义文本handler（中文友好的格式）
func newTextHandler(w io.Writer, level slog.Level) slog.Handler {
	return slog.NewTextHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// 自定义时间格式（仅处理slog内部的TimeKey）
			if a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				t := a.Value.Time()
				return slog.String("time", t.Format("2006-01-02 15:04:05"))
			}
			// 自定义级别显示
			if a.Key == slog.LevelKey {
				level := a.Value.Any().(slog.Level)
				levelStr := ""
				switch level {
				case slog.LevelDebug:
					levelStr = "DEBUG"
				case slog.LevelInfo:
					levelStr = "INFO "
				case slog.LevelWarn:
					levelStr = "WARN "
				case slog.LevelError:
					levelStr = "ERROR"
				}
				return slog.String("level", levelStr)
			}
			return a
		},
	})
}

// 开启debug日志文件
func (l *Logger) EnableDebugLog(filePath string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// 如果已经有文件打开，先关闭
	if l.debugFile != nil {
		l.debugFile.Close()
	}

	// 创建日志文件
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %w", err)
	}

	l.debugFile = f

	// 同时输出到控制台、主日志文件和临时 debug 文件
	writers := []io.Writer{os.Stdout, f}
	if fileWriter != nil {
		writers = append(writers, fileWriter)
	}
	handler := newTextHandler(io.MultiWriter(writers...), slog.LevelDebug)
	l.Logger = slog.New(handler)

	l.Info("Debug日志已开启", "file", filePath)

	return nil
}

// 关闭debug日志，返回文件路径
func (l *Logger) DisableDebugLog() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.debugFile == nil {
		return ""
	}

	filePath := l.debugFile.Name()

	l.Info("Debug日志即将关闭", "file", filePath)

	l.debugFile.Close()
	l.debugFile = nil

	// 恢复到控制台 + 主日志文件输出
	var w io.Writer = os.Stdout
	if fileWriter != nil {
		w = io.MultiWriter(os.Stdout, fileWriter)
	}
	handler := newTextHandler(w, slog.LevelInfo)
	l.Logger = slog.New(handler)

	return filePath
}

// 检查debug模式是否开启
func (l *Logger) IsDebugEnabled() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.debugFile != nil
}

// 获取当前debug文件路径
func (l *Logger) GetDebugFilePath() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.debugFile != nil {
		return l.debugFile.Name()
	}
	return ""
}

// 脱敏敏感信息
func sanitizeArgs(args []any) []any {
	if len(args) == 0 {
		return args
	}

	result := make([]any, len(args))
	copy(result, args)

	for i := 0; i < len(result)-1; i += 2 {
		if keyStr, ok := result[i].(string); ok {
			keyLower := strings.ToLower(keyStr)
			if strings.Contains(keyLower, "password") ||
				strings.Contains(keyLower, "token") ||
				strings.Contains(keyLower, "secret") ||
				strings.Contains(keyLower, "key") && !strings.Contains(keyLower, "key=") {
				result[i+1] = "***"
			}
		}
	}

	return result
}

// 全局便捷方法
func Info(msg string, args ...any) {
	GetLogger().Info(msg, sanitizeArgs(args)...)
}

func Warn(msg string, args ...any) {
	GetLogger().Warn(msg, sanitizeArgs(args)...)
}

func Error(msg string, args ...any) {
	GetLogger().Error(msg, sanitizeArgs(args)...)
}

func Debug(msg string, args ...any) {
	GetLogger().Debug(msg, sanitizeArgs(args)...)
}

// 全局开启debug
func EnableDebug(filePath string) error {
	return GetLogger().EnableDebugLog(filePath)
}

// 全局关闭debug
func DisableDebug() string {
	return GetLogger().DisableDebugLog()
}

// 全局检查debug状态
func IsDebugEnabled() bool {
	return GetLogger().IsDebugEnabled()
}
