// Command upload-sink is a deliberately tiny, test-owned HTTP endpoint for
// exercising an HTTPS upload path through Render.  Render terminates HTTPS at
// its edge; the container only needs to serve its injected PORT.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	UploadPathEnv      = "UPLOAD_PATH"
	UploadPathFilePath = "/etc/secrets/upload-path"
	MaxUploadBytes     = int64(2 * 1024 * 1024)

	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 30 * time.Second
	shutdownTimeout   = 5 * time.Second
	maxHeaderBytes    = 16 * 1024
)

var uploadPathPattern = regexp.MustCompile(`^/upload/[0-9a-f]{32,}$`)

var (
	errInvalidPort       = errors.New("PORT must be a valid TCP port")
	errInvalidUploadPath = errors.New("UPLOAD_PATH must match /upload/<32+ lowercase hex>")
	errInvalidArguments  = errors.New("upload-sink arguments are invalid")
	errIncomplete        = errors.New("upload body is incomplete")
	errExtra             = errors.New("upload body contains extra bytes")
	errNoProgress        = errors.New("upload body made no progress")
)

type Config struct {
	Port       int
	UploadPath string
}

// LoadConfig validates the only two values needed to start the sink.  Error
// messages intentionally contain no user-controlled request data.
func LoadConfig() (Config, error) {
	return loadConfig(nil)
}

func loadConfig(args []string) (Config, error) {
	portText := os.Getenv("PORT")
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return Config{}, errInvalidPort
	}

	uploadPath, err := loadUploadPath(args)
	if err != nil {
		return Config{}, err
	}
	if !uploadPathPattern.MatchString(uploadPath) {
		return Config{}, errInvalidUploadPath
	}
	return Config{Port: port, UploadPath: uploadPath}, nil
}

func loadUploadPath(args []string) (string, error) {
	if len(args) == 0 {
		return os.Getenv(UploadPathEnv), nil
	}
	if len(args) != 1 || !strings.HasPrefix(args[0], "--path-file=") || strings.TrimPrefix(args[0], "--path-file=") != UploadPathFilePath {
		return "", errInvalidArguments
	}
	return loadUploadPathFile(UploadPathFilePath)
}

func loadUploadPathFile(path string) (string, error) {
	// Render may expose a runtime secret through a provider-managed symlink.
	// Open the fixed path, then validate and read only the opened descriptor;
	// this permits that mount representation without a post-open path race.
	file, err := os.Open(path)
	if err != nil {
		return "", errInvalidUploadPath
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256 {
		return "", errInvalidUploadPath
	}
	contents, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil || len(contents) > 256 {
		return "", errInvalidUploadPath
	}
	value := string(contents)
	value = strings.TrimSuffix(value, "\n")
	if strings.ContainsAny(value, "\r\n") {
		return "", errInvalidUploadPath
	}
	return value, nil
}

// NewHandler returns the secretless request boundary.  An invalid configured
// path simply makes every upload request fail closed; LoadConfig rejects it
// before a production listener is opened.
func NewHandler(uploadPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			defer r.Body.Close()
		}

		if r.URL == nil || r.URL.RawQuery != "" || r.URL.Fragment != "" || (r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path) {
			writeStatus(w, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			writeStatus(w, http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != uploadPath || !uploadPathPattern.MatchString(uploadPath) {
			writeStatus(w, http.StatusNotFound)
			return
		}

		if !contentLengthHeaderMatches(r) || r.ContentLength <= 0 {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		if r.ContentLength > MaxUploadBytes {
			writeStatus(w, http.StatusRequestEntityTooLarge)
			return
		}
		if err := consumeExactly(r.Body, r.ContentLength); err != nil {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		writeStatus(w, http.StatusNoContent)
	})
}

// NewServer constructs a bounded server. Standard-library diagnostics are
// retained byte-for-byte on stderr in the private Render service logs; they
// must not be discarded, summarized, hashed, or otherwise suppressed.
func NewServer(addr, uploadPath string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           NewHandler(uploadPath),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
}

func contentLengthHeaderMatches(r *http.Request) bool {
	values := r.Header.Values("Content-Length")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	if values[0] == "" {
		return false
	}
	for _, character := range values[0] {
		if character < '0' || character > '9' {
			return false
		}
	}
	length, err := strconv.ParseInt(values[0], 10, 64)
	return err == nil && length == r.ContentLength
}

func consumeExactly(body io.Reader, expected int64) error {
	if body == nil {
		return errIncomplete
	}
	var buffer [32 * 1024]byte
	remaining := expected
	emptyReads := 0
	for remaining > 0 {
		want := int64(len(buffer))
		if remaining < want {
			want = remaining
		}
		n, err := body.Read(buffer[:want])
		if n < 0 || int64(n) > want {
			return errExtra
		}
		if n > 0 {
			remaining -= int64(n)
			emptyReads = 0
		} else if err == nil {
			emptyReads++
			if emptyReads >= 100 {
				return errNoProgress
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) && remaining == 0 {
				break
			}
			if errors.Is(err, io.EOF) {
				return errIncomplete
			}
			return err
		}
	}

	// A custom reader may expose bytes beyond Content-Length.  Probe one byte
	// so tests and non-net/http callers cannot smuggle an oversized body.
	var extra [1]byte
	n, err := body.Read(extra[:])
	if n > 0 {
		return errExtra
	}
	if err == nil {
		return errNoProgress
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func writeStatus(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
}

func run(ctx context.Context) error {
	return runArgs(ctx, os.Args[1:])
}

func runArgs(ctx context.Context, args []string) error {
	config, err := loadConfig(args)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(config.Port))
	if err != nil {
		return fmt.Errorf("could not listen on PORT: %w", err)
	}
	server := NewServer(listener.Addr().String(), config.UploadPath)
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("upload sink server stopped: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("upload sink shutdown failed: %w", err)
		}
		return nil
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
