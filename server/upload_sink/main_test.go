package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const testUploadPath = "/upload/0123456789abcdef0123456789abcdef"

func TestLoadConfig(t *testing.T) {
	t.Setenv("PORT", "43123")
	t.Setenv(UploadPathEnv, testUploadPath)
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.Port != 43123 || config.UploadPath != testUploadPath {
		t.Fatalf("config = %+v", config)
	}

	for _, test := range []struct {
		name string
		port string
		path string
	}{
		{"missing-port", "", testUploadPath},
		{"bad-port", "not-a-port", testUploadPath},
		{"zero-port", "0", testUploadPath},
		{"too-large-port", "65536", testUploadPath},
		{"missing-path", "43123", ""},
		{"short-path", "43123", "/upload/0123456789abcdef0123456789abcdef0/extra"},
		{"uppercase-path", "43123", "/upload/0123456789ABCDEF0123456789abcdef"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PORT", test.port)
			t.Setenv(UploadPathEnv, test.path)
			if _, err := LoadConfig(); err == nil {
				t.Fatal("LoadConfig unexpectedly accepted invalid environment")
			}
		})
	}
}

func TestLoadConfigReadsOwnerOnlyPathFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upload-path")
	if err := os.WriteFile(path, []byte(testUploadPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := loadUploadPathFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if value != testUploadPath {
		t.Fatalf("upload path = %q, want %q", value, testUploadPath)
	}

	if _, err := loadUploadPath([]string{"--path-file=" + path}); err == nil {
		t.Fatal("loadUploadPath unexpectedly accepted a non-Render secret path")
	}
	if _, err := loadUploadPath([]string{"--unexpected"}); err == nil {
		t.Fatal("loadUploadPath unexpectedly accepted an unknown argument")
	}
}

func TestLoadUploadPathFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	path := filepath.Join(root, "upload-path")
	if err := os.WriteFile(target, []byte(testUploadPath), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUploadPathFile(path); err == nil {
		t.Fatal("loadUploadPathFile unexpectedly followed a symlink")
	}
}

func TestUploadPathValidation(t *testing.T) {
	for _, test := range []struct {
		path  string
		valid bool
	}{
		{testUploadPath, true},
		{"/upload/" + strings.Repeat("a", 31), false},
		{"/upload/" + strings.Repeat("a", 32), true},
		{"/upload/" + strings.Repeat("a", 64), true},
		{"/upload/0123456789abcdef0123456789abcdeg", false},
		{"/Upload/0123456789abcdef0123456789abcdef", false},
		{"/upload/0123456789abcdef0123456789abcdef/extra", false},
	} {
		if got := uploadPathPattern.MatchString(test.path); got != test.valid {
			t.Errorf("MatchString(%q) = %v, want %v", test.path, got, test.valid)
		}
	}
}

func TestHandlerHealthzAndRouteRejections(t *testing.T) {
	handler := NewHandler(testUploadPath)
	for _, test := range []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"health", http.MethodGet, "/healthz", http.StatusNoContent},
		{"health-query", http.MethodGet, "/healthz?x=1", http.StatusNotFound},
		{"health-post", http.MethodPost, "/healthz", http.StatusNotFound},
		{"upload-query", http.MethodPost, testUploadPath + "?x=1", http.StatusNotFound},
		{"upload-escaped-path", http.MethodPost, "/upload/%30" + testUploadPath[len("/upload/1"):], http.StatusNotFound},
		{"upload-fragment", http.MethodPost, testUploadPath + "#fragment", http.StatusNotFound},
		{"wrong-path", http.MethodPost, "/upload/0123456789abcdef0123456789abcdef0", http.StatusNotFound},
		{"wrong-method", http.MethodPut, testUploadPath, http.StatusNotFound},
		{"invalid-configured-path", http.MethodPost, testUploadPath, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			configured := testUploadPath
			if test.name == "invalid-configured-path" {
				configured = "/upload/not-random"
			}
			request := httptest.NewRequest(test.method, "https://sink"+test.path, nil)
			recording := httptest.NewRecorder()
			selectedHandler := handler
			if configured != testUploadPath {
				selectedHandler = NewHandler(configured)
			}
			selectedHandler.ServeHTTP(recording, request)
			if recording.Code != test.want {
				t.Fatalf("status = %d, want %d", recording.Code, test.want)
			}
			if recording.Body.Len() != 0 {
				t.Fatalf("response body is not empty: %q", recording.Body.String())
			}
		})
	}
}

func TestHandlerAcceptsExactBodyAndDiscardsIt(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 4097)
	request := httptest.NewRequest(http.MethodPost, "https://sink"+testUploadPath, bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	recording := httptest.NewRecorder()
	NewHandler(testUploadPath).ServeHTTP(recording, request)
	if recording.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recording.Code, http.StatusNoContent)
	}
	if recording.Body.Len() != 0 {
		t.Fatalf("response body is not empty: %q", recording.Body.String())
	}
}

func TestHandlerAcceptsExactlyOneMiBBody(t *testing.T) {
	body := bytes.Repeat([]byte{0x5a}, 1<<20)
	request := httptest.NewRequest(http.MethodPost, "https://sink"+testUploadPath, bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	recording := httptest.NewRecorder()
	NewHandler(testUploadPath).ServeHTTP(recording, request)
	if recording.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", recording.Code, http.StatusNoContent)
	}
	if recording.Body.Len() != 0 {
		t.Fatalf("response body is not empty: %q", recording.Body.String())
	}
}

func TestHandlerRejectsInvalidLengthsAndBodies(t *testing.T) {
	for _, test := range []struct {
		name          string
		body          io.Reader
		contentLength int64
		want          int
	}{
		{"missing", strings.NewReader("x"), 0, http.StatusBadRequest},
		{"chunked-or-unknown", strings.NewReader("x"), -1, http.StatusBadRequest},
		{"oversize", strings.NewReader("x"), MaxUploadBytes + 1, http.StatusRequestEntityTooLarge},
		{"incomplete", strings.NewReader("short"), 6, http.StatusBadRequest},
		{"extra", strings.NewReader("abcdef"), 5, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://sink"+testUploadPath, test.body)
			request.ContentLength = test.contentLength
			recording := httptest.NewRecorder()
			NewHandler(testUploadPath).ServeHTTP(recording, request)
			if recording.Code != test.want {
				t.Fatalf("status = %d, want %d", recording.Code, test.want)
			}
		})
	}
}

func TestHandlerRejectsConflictingContentLengthHeader(t *testing.T) {
	for _, value := range []string{"2", "+1", " 1"} {
		t.Run(value, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://sink"+testUploadPath, strings.NewReader("x"))
			request.ContentLength = 1
			request.Header.Set("Content-Length", value)
			recording := httptest.NewRecorder()
			NewHandler(testUploadPath).ServeHTTP(recording, request)
			if recording.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recording.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestHTTPSIntegration(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("local loopback sockets are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(NewHandler(testUploadPath))
	server.Listener = listener
	server.StartTLS()
	defer server.Close()

	response, err := server.Client().Post(server.URL+testUploadPath, "application/octet-stream", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("upload status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	health, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()
	if health.StatusCode != http.StatusNoContent {
		t.Fatalf("health status = %d, want %d", health.StatusCode, http.StatusNoContent)
	}
}

func TestServerTimeoutsAreBoundedAndDiagnosticsConfigured(t *testing.T) {
	server := NewServer(":0", testUploadPath)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("server timeouts must all be positive: %+v", server)
	}
	if server.MaxHeaderBytes <= 0 {
		t.Fatal("MaxHeaderBytes must be positive")
	}
	if server.ErrorLog == nil {
		t.Fatal("ErrorLog must be configured")
	}
}

func TestServerDiagnosticsAreRetainedUnmodifiedOnStderr(t *testing.T) {
	server := NewServer(":0", testUploadPath)
	if server.ErrorLog.Writer() != os.Stderr {
		t.Fatal("server diagnostics must be retained directly on stderr")
	}
}

func TestRunPreservesListenDiagnostic(t *testing.T) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skipf("local loopback sockets are unavailable: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()

	t.Setenv("PORT", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	t.Setenv(UploadPathEnv, testUploadPath)
	err = runArgs(context.Background(), nil)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "address already in use") {
		t.Fatalf("listen error = %v, want the underlying bind diagnostic", err)
	}
}
