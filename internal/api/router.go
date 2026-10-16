package api

import (
	"github.com/gin-gonic/gin"
)

// NewRouter wires every endpoint onto the given manager.
func NewRouter(mgr *Manager) *gin.Engine {
	s := &Server{mgr: mgr}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.GET("/healthz", s.health)
	r.GET("/device", s.device)

	// One-shot: PSSH in, keys out (uses the configured license server).
	r.POST("/keys", s.open)

	// Two-step, for servers that need custom handling.
	r.POST("/session", s.open)
	r.GET("/session/:id", s.getSession)
	r.GET("/session/:id/challenge", s.getChallenge)
	r.GET("/session/:id/keys", s.getKeys)
	r.GET("/session/:id/keys.txt", s.getKeysText)
	r.POST("/session/:id/update", s.update)
	r.DELETE("/session/:id", s.closeSession)

	return r
}
