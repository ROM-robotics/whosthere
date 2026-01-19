package cmd

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/ramonvermeulen/whosthere/internal/core/config"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery/arp"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery/mdns"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery/ssdp"
	"github.com/ramonvermeulen/whosthere/internal/core/logging"
	"github.com/ramonvermeulen/whosthere/internal/core/oui"
	"github.com/ramonvermeulen/whosthere/internal/core/state"
	"github.com/ramonvermeulen/whosthere/internal/core/version"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run whosthere in daemon mode with an HTTP API",
	Long: `Run whosthere in daemon mode, continuously scanning the network and providing live device data via HTTP API.

Examples:
  whosthere daemon --port 8080
`,
	RunE: runDaemon,
}

func runDaemon(cmd *cobra.Command, _ []string) error {
	port, _ := cmd.Flags().GetString("port")
	if port == "" {
		port = "8080"
		zap.L().Info("no port specified, using default port", zap.String("port", port))
	}

	level := logging.LevelFromEnv(zapcore.InfoLevel)
	_, _, err := logging.Init(level, true)
	if err != nil {
		return err
	}

	ctx := context.Background()

	cfg, err := config.Load("")
	if err != nil {
		zap.L().Error("failed to load config", zap.Error(err))
		return err
	}

	ouiDB, err := oui.Init(ctx)
	if err != nil {
		zap.L().Warn("failed to initialize OUI DB; continuing without OUI", zap.Error(err))
		ouiDB = nil
	}

	appState := state.NewAppState(cfg, version.Version)

	var scList []discovery.Scanner
	sweeper := arp.NewSweeper(5*time.Minute, time.Minute)
	scList = append(scList, &ssdp.Scanner{}, arp.NewScanner(sweeper), &mdns.Scanner{})

	eng := discovery.NewEngine(scList, discovery.WithTimeout(30*time.Second), discovery.WithOUIRegistry(ouiDB))

	http.HandleFunc("/devices", func(w http.ResponseWriter, r *http.Request) {
		handleDevices(w, r, appState)
	})
	http.HandleFunc("/devices/", func(w http.ResponseWriter, r *http.Request) {
		handleDeviceByIP(w, r, appState)
	})
	http.HandleFunc("/health", handleHealth)

	go func() {
		zap.L().Info("starting HTTP server", zap.String("port", port))
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			zap.L().Error("HTTP server failed", zap.Error(err))
		}
	}()

	for {
		zap.L().Info("starting scan cycle")
		_, err := eng.Stream(ctx, func(d discovery.Device) {
			appState.UpsertDevice(&d)
		})
		if err != nil {
			zap.L().Error("scan failed", zap.Error(err))
		}
		time.Sleep(cfg.ScanInterval)
	}
}

func handleDevices(w http.ResponseWriter, r *http.Request, appState *state.AppState) {
	zap.L().Info("incoming request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
	devices := appState.DevicesSnapshot()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(devices); err != nil {
		http.Error(w, "Failed to encode devices", http.StatusInternalServerError)
		return
	}
}

func handleDeviceByIP(w http.ResponseWriter, r *http.Request, appState *state.AppState) {
	zap.L().Info("incoming request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
	ipStr := strings.TrimPrefix(r.URL.Path, "/devices/")
	if ipStr == "" {
		http.NotFound(w, r)
		return
	}
	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}
	device, ok := appState.GetDevice(ipStr)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(device); err != nil {
		http.Error(w, "Failed to encode device", http.StatusInternalServerError)
		return
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	zap.L().Info("incoming request", zap.String("method", r.Method), zap.String("path", r.URL.Path))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func init() {
	daemonCmd.Flags().StringP("port", "p", "", "Port for the HTTP API server")
	rootCmd.AddCommand(daemonCmd)
}
