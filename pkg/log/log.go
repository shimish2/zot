package log

import (
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
)

// Logger extends zerolog's Logger.
type Logger struct {
	zerolog.Logger
}

func (l Logger) Println(v ...interface{}) {
	l.Logger.Error().Msg("panic recovered")
}

func NewLogger(level string, output string) Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	lvl, err := zerolog.ParseLevel(level)

	if err != nil {
		panic(err)
	}

	zerolog.SetGlobalLevel(lvl)

	var log zerolog.Logger

	if output == "" {
		log = zerolog.New(os.Stdout)
	} else {
		file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		log = zerolog.New(file)
	}

	return Logger{Logger: log.With().Caller().Timestamp().Logger()}
}

type statusWriter struct {
	http.ResponseWriter
	status int
	length int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}

	n, err := w.ResponseWriter.Write(b)
	w.length += n

	return n, err
}

func SessionLogger(log Logger) mux.MiddlewareFunc {
	l := log.With().Str("module", "http").Logger()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Start timer
			start := time.Now()
			path := r.URL.Path
			raw := r.URL.RawQuery

			sw := statusWriter{ResponseWriter: w}

			// Process request
			next.ServeHTTP(&sw, r)

			// Stop timer
			end := time.Now()
			latency := end.Sub(start)
			if latency > time.Minute {
				// Truncate in a golang < 1.8 safe way
				latency -= latency % time.Second
			}
			clientIP := r.RemoteAddr
			method := r.Method
			headers := map[string][]string{}
			for key, value := range r.Header {
				if key == "Authorization" { // anonymize from logs
					value = []string{"******"}
				}
				headers[key] = value
			}
			statusCode := sw.status
			bodySize := sw.length
			if raw != "" {
				path = path + "?" + raw
			}

			l.Info().
				Str("clientIP", clientIP).
				Str("method", method).
				Str("path", path).
				Int("statusCode", statusCode).
				Str("latency", latency.String()).
				Int("bodySize", bodySize).
				Interface("headers", headers).
				Msg("HTTP API")
		})
	}
}
