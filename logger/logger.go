package logger

import (
	"io"
	"log/syslog"
	"os"
	"sync"
	"time"

	"github.com/activecm/ritav2/config"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/pkgerrors"
	"github.com/spf13/afero"
)

var once sync.Once
var zLogger zerolog.Logger
var DebugMode bool

type LevelWriter zerolog.LevelWriter

type LevelWriterAdapter struct {
	zerolog.LevelWriterAdapter
	Level zerolog.Level
}

// zerolog allows for logging at the following levels (from highest to lowest):
// panic (zerolog.PanicLevel, 5)
// fatal (zerolog.FatalLevel, 4)
// error (zerolog.ErrorLevel, 3)
// warn (zerolog.WarnLevel, 2)
// info (zerolog.InfoLevel, 1)
// debug (zerolog.DebugLevel, 0)
// trace (zerolog.TraceLevel, -1)

// GetLogger returns a logger instance, initializing it if necessary
func GetLogger() zerolog.Logger {
	// ensure that the logger is only created once
	once.Do(func() {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

		// create console writer
		var output io.Writer = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		tmpLogger := zerolog.New(output).With().Timestamp().Logger()

		// get logging settings from config
		cfg, err := config.GetConfig()
		if err != nil {
			cfg, err = config.LoadConfig(afero.NewOsFs(), config.DefaultConfigPath)
			if err != nil {
				tmpLogger.Err(err).Msg("unable to read logging settings from config, reverting to basic logging settings... ")
				cfg.LoggingEnabled = false
				cfg.LogLevel = 1
			}
		}

		logLevel := zerolog.Level(1) // cfg.LogLevel)

		var writers []io.Writer

		// set both file writer and stdout logging level to debug if DebugMode is set
		if DebugMode {
			logLevel = zerolog.DebugLevel
		}

		if cfg.LoggingEnabled {
			// set up syslog
			syslogAddress := os.Getenv("SYSLOG_ADDRESS")
			if syslogAddress == "" {
				tmpLogger.Fatal().Msg("environment variable: SYSLOG_ADDRESS is not set, exiting")
			}
			zsyslog, err := syslog.Dial("udp", syslogAddress, syslog.LOG_KERN|syslog.LOG_EMERG|syslog.LOG_ERR|syslog.LOG_INFO|syslog.LOG_CRIT|syslog.LOG_WARNING|syslog.LOG_NOTICE|syslog.LOG_DEBUG, "rita")
			if err != nil {
				panic(err)
			}

			// create leveled writer to syslog
			var syslogWriter LevelWriter = LevelWriterAdapter{Level: logLevel, LevelWriterAdapter: zerolog.LevelWriterAdapter{Writer: zsyslog}}
			syslogLogger := &zerolog.FilteredLevelWriter{
				Writer: syslogWriter,
				Level:  logLevel,
			}

			writers = append(writers, syslogLogger)
		}

		// create leveled writer to stdout
		var stdWriter LevelWriter = LevelWriterAdapter{Level: logLevel, LevelWriterAdapter: zerolog.LevelWriterAdapter{Writer: output}}
		stdLogger := &zerolog.FilteredLevelWriter{
			Writer: stdWriter,
			Level:  logLevel,
		}
		writers = append(writers, stdLogger)

		// log to both stdout and file
		output = zerolog.MultiLevelWriter(writers...)
		zLogger = zerolog.New(output).With().Timestamp().Logger()
	})
	return zLogger
}

func (lw LevelWriterAdapter) WriteLevel(l zerolog.Level, p []byte) (n int, err error) {
	if l >= lw.Level {
		return lw.Write(p)
	}
	return 0, nil
}
