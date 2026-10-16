// Package api provides the HTTP surface over a Widevine CDM device.
package api

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"chromecdm/internal/cdm"
)

// LicenseClient posts a challenge to a license server and returns the
// raw license response.
type LicenseClient struct {
	URL     string
	Headers map[string]string
	Client  *http.Client
}

// Post sends the challenge as an octet-stream body.
func (l *LicenseClient) Post(challenge []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, l.URL, bytesReader(challenge))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range l.Headers {
		req.Header.Set(k, v)
	}
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := readAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// Session is a CDM session plus its result state.
type Session struct {
	ID        string
	CreatedAt time.Time

	inner     *cdm.Session
	Challenge []byte

	mu      sync.Mutex
	Keys    []cdm.Key
	License []byte
	Status  string
	Err     string
}

// Manager owns one device and every session opened against it.
type Manager struct {
	dev    *cdm.Device
	lic    *LicenseClient
	mu     sync.RWMutex
	byID   map[string]*Session
	nextID int
}

// NewManager binds a device and license client.
func NewManager(dev *cdm.Device, lic *LicenseClient) *Manager {
	return &Manager{dev: dev, lic: lic, byID: make(map[string]*Session)}
}

// Device returns the loaded device.
func (m *Manager) Device() *cdm.Device { return m.dev }

// OpenSession builds a new session and its challenge.
func (m *Manager) OpenSession(psshRaw []byte) (*Session, error) {
	inner, err := m.dev.OpenSession(psshRaw)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.nextID++
	id := fmt.Sprintf("sess-%04d", m.nextID)
	s := &Session{
		ID:        id,
		CreatedAt: time.Now(),
		inner:     inner,
		Challenge: inner.Challenge,
		Status:    "challenge_ready",
	}
	m.byID[id] = s
	m.mu.Unlock()
	return s, nil
}

// Get returns a session by id.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.byID[id]
	return s, ok
}

// Count reports live sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byID)
}

// Close removes a session.
func (m *Manager) Close(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[id]; !ok {
		return false
	}
	delete(m.byID, id)
	return true
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

var _ = gin.H{}
