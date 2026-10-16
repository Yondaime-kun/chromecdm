// Command chromecdm serves a Widevine CDM over HTTP.
//
// Usage:
//
//	chromecdm -device device.wvd -license https://license-server/path
//
// Flags fall back to CDM_DEVICE / LICENSE_URL env vars.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chromecdm/internal/api"
	"chromecdm/internal/cdm"
	"chromecdm/internal/version"
)

func main() {
	devicePath := flag.String("device", envOr("CDM_DEVICE", "device.wvd"),
		"path to a .wvd Widevine device file")
	licenseURL := flag.String("license", envOr("LICENSE_URL", ""),
		"license server URL (or LICENSE_URL env)")
	addr := flag.String("addr", envOr("LISTEN_ADDR", ":8443"), "listen address")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("chromecdm %s", version.String())
		return
	}

	dev, err := cdm.Load(*devicePath)
	if err != nil {
		log.Fatalf("device: %v", err)
	}
	log.Printf("device loaded: %s", dev.Path())

	var lic *api.LicenseClient
	if *licenseURL != "" {
		lic = &api.LicenseClient{
			URL: *licenseURL,
			Headers: map[string]string{
				"User-Agent": envOr("LICENSE_UA", "chromecdm/1.0"),
			},
		}
		log.Printf("license server: %s", *licenseURL)
	} else {
		log.Printf("no license server configured; /keys will return challenges only")
	}

	mgr := api.NewManager(dev, lic)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewRouter(mgr),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
