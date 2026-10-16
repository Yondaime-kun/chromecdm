package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Server holds the manager the handlers drive.
type Server struct {
	mgr *Manager
}

func (s *Server) health(c *gin.Context) { c.String(http.StatusOK, "ok") }

func (s *Server) device(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"device":         s.mgr.Device().Path(),
		"sessions":       s.mgr.Count(),
		"license_url":    s.licURL(),
		"key_system":     "com.widevine.alpha",
		"security_level": 3,
	})
}

func (s *Server) licURL() string {
	if s.mgr.lic == nil {
		return ""
	}
	return s.mgr.lic.URL
}

// --- sessions ---

type openReq struct {
	// PSSH is base64. Either a raw protobuf PSSH, a full pssh box, or the
	// WidevinePsshData body.
	PSSH string `json:"pssh" binding:"required"`

	// LicenseURL overrides the configured server for this session.
	LicenseURL string `json:"license_url"`
}

// open creates a session, fetches the license, and returns the keys.
// This is the one-shot path: PSSH in, keys out.
func (s *Server) open(c *gin.Context) {
	var req openReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pssh, err := decodeB64(req.PSSH)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pssh not valid base64"})
		return
	}

	sess, err := s.mgr.OpenSession(pssh)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	lic := s.mgr.lic
	if req.LicenseURL != "" {
		lic = &LicenseClient{URL: req.LicenseURL, Headers: s.mgr.lic.Headers}
	}
	if lic == nil || lic.URL == "" {
		// No license server: return the challenge only.
		c.JSON(http.StatusOK, gin.H{
			"session_id":    sess.ID,
			"status":        sess.Status,
			"challenge":     b64(sess.Challenge),
			"challenge_len": len(sess.Challenge),
			"keys":          []any{},
			"note":          "no license_url configured; post the challenge yourself",
		})
		return
	}

	body, code, err := lic.Post(sess.Challenge)
	if err != nil {
		sess.Status = "license_error"
		sess.Err = err.Error()
		c.JSON(http.StatusBadGateway, gin.H{
			"session_id": sess.ID,
			"status":     sess.Status,
			"error":      err.Error(),
			"challenge":  b64(sess.Challenge),
		})
		return
	}
	if code != http.StatusOK {
		sess.Status = "license_http_error"
		c.JSON(http.StatusBadGateway, gin.H{
			"session_id":   sess.ID,
			"status":       sess.Status,
			"license_http": code,
			"license_body": string(body),
			"challenge":    b64(sess.Challenge),
		})
		return
	}

	keys, err := sess.inner.ParseLicense(body)
	if err != nil {
		sess.Status = "parse_error"
		c.JSON(http.StatusBadGateway, gin.H{
			"session_id": sess.ID,
			"status":     sess.Status,
			"error":      err.Error(),
		})
		return
	}
	sess.mu.Lock()
	sess.Keys = keys
	sess.License = body
	sess.Status = "keys_ready"
	sess.mu.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"session_id":    sess.ID,
		"status":        sess.Status,
		"challenge_len": len(sess.Challenge),
		"license_len":   len(body),
		"key_count":     len(keys),
		"keys":          keysToJSON(keys),
		"keys_text":     keysText(keys),
	})
}

// getSession returns a session snapshot.
func (s *Server) getSession(c *gin.Context) {
	sess, ok := s.mgr.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session"})
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"session_id":    sess.ID,
		"status":        sess.Status,
		"challenge_len": len(sess.Challenge),
		"key_count":     len(sess.Keys),
		"keys":          keysToJSON(sess.Keys),
		"keys_text":     keysText(sess.Keys),
		"created_at":    sess.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// getKeys is keys-only.
func (s *Server) getKeys(c *gin.Context) {
	sess, ok := s.mgr.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session"})
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"session_id": sess.ID,
		"key_count":  len(sess.Keys),
		"keys":       keysToJSON(sess.Keys),
		"keys_text":  keysText(sess.Keys),
	})
}

// getKeysText emits KID:KEY lines for piping.
func (s *Server) getKeysText(c *gin.Context) {
	sess, ok := s.mgr.Get(c.Param("id"))
	if !ok {
		c.String(http.StatusNotFound, "unknown session\n")
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, keysText(sess.Keys))
}

// getChallenge returns just the license challenge.
func (s *Server) getChallenge(c *gin.Context) {
	sess, ok := s.mgr.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id":    sess.ID,
		"challenge":     b64(sess.Challenge),
		"challenge_len": len(sess.Challenge),
	})
}

// update takes a license response for an existing session.
type updateReq struct {
	License string `json:"license" binding:"required"`
}

func (s *Server) update(c *gin.Context) {
	sess, ok := s.mgr.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session"})
		return
	}
	var req updateReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	lic, err := decodeB64(req.License)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "license not valid base64"})
		return
	}
	keys, err := sess.inner.ParseLicense(lic)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	sess.mu.Lock()
	sess.Keys = keys
	sess.License = lic
	sess.Status = "keys_ready"
	sess.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{
		"session_id": sess.ID,
		"key_count":  len(keys),
		"keys":       keysToJSON(keys),
		"keys_text":  keysText(keys),
	})
}

func (s *Server) closeSession(c *gin.Context) {
	if !s.mgr.Close(c.Param("id")) {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"closed": c.Param("id")})
}
