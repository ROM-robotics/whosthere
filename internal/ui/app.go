package ui

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dece2183/go-clipboard"
	"github.com/gdamore/tcell/v2"
	"github.com/ramonvermeulen/whosthere/internal/core"
	"github.com/ramonvermeulen/whosthere/internal/core/config"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery"
	"github.com/ramonvermeulen/whosthere/internal/core/oui"
	"github.com/ramonvermeulen/whosthere/internal/core/probe"
	"github.com/ramonvermeulen/whosthere/internal/core/state"
	"github.com/ramonvermeulen/whosthere/internal/ui/events"
	"github.com/ramonvermeulen/whosthere/internal/ui/routes"
	"github.com/ramonvermeulen/whosthere/internal/ui/theme"
	"github.com/ramonvermeulen/whosthere/internal/ui/views"
	"github.com/rivo/tview"
	"go.uber.org/zap"
)

const (
	refreshInterval = 1 * time.Second
)

// App represents the main TUI application.
type App struct {
	*tview.Application
	pages         *tview.Pages
	engine        *discovery.Engine
	state         *state.AppState
	scanTicker    *time.Ticker
	refreshTicker *time.Ticker
	cfg           *config.Config
	events        chan events.Event
	emit          func(events.Event)
	portScanner   *discovery.PortScanner
	isReady       bool
	clipboard     *clipboard.Clipboard
	ouiDB         *oui.Registry
	scanCancel    context.CancelFunc
	scanMu        sync.Mutex
	prober        *probe.Prober
	iface         *discovery.InterfaceInfo
}

func NewApp(cfg *config.Config, ouiDB *oui.Registry, version string) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	app := tview.NewApplication()
	appState := state.NewAppState(cfg, version)

	a := &App{
		Application: app,
		state:       appState,
		cfg:         cfg,
		events:      make(chan events.Event, 100),
		clipboard:   clipboard.New(clipboard.ClipboardOptions{Primary: false}),
	}

	a.emit = func(e events.Event) {
		a.events <- e
	}
	a.pages = tview.NewPages()

	a.applyTheme(appState.CurrentTheme())
	a.setupPages(cfg)
	err := a.setupEngine(cfg, ouiDB)
	if err != nil {
		return nil, fmt.Errorf("failed to setup engine: %w", err)
	}

	// Store ouiDB for engine rebuilds when switching interfaces
	a.ouiDB = ouiDB

	// Populate available interfaces and track the active one
	a.state.SetAvailableInterfaces(discovery.ListAllInterfaces())
	if a.engine != nil && len(a.engine.Scanners) > 0 {
		// Determine active interface from the engine's first scanner's interface info
		iface, ifErr := discovery.NewInterfaceInfo(cfg.NetworkInterface)
		if ifErr == nil {
			a.state.SetActiveInterface(iface.Interface.Name)
			if iface.IPv4Addr != nil {
				a.state.SetLocalIP(iface.IPv4Addr.String())
			}
		}
	}

	app.SetRoot(a.pages, true)
	app.SetInputCapture(a.handleGlobalKeys)
	app.EnableMouse(true)

	return a, nil
}

func (a *App) Run() error {
	zap.L().Debug("App Run started")
	go a.handleEvents()
	a.startUIRefreshLoop()

	if a.cfg != nil && a.cfg.Splash.Enabled {
		go func(delay time.Duration) {
			defer func() {
				if r := recover(); r != nil {
					zap.L().Error("Panic in splash delay", zap.Any("panic", r))
				}
			}()
			time.Sleep(delay)
			a.emit(events.NavigateTo{Route: routes.RouteDashboard})
			a.isReady = true
		}(a.cfg.Splash.Delay)
	} else {
		a.isReady = true
	}

	if a.engine != nil && a.cfg != nil {
		a.startDiscoveryScanLoop()
	}

	return a.Application.Run()
}

func (a *App) setupPages(cfg *config.Config) {
	dashboardPage := views.NewDashboardView(a.emit, a.QueueUpdateDraw)
	detailPage := views.NewDetailView(a.emit, a.QueueUpdateDraw)
	splashPage := views.NewSplashView(a.emit)
	themePickerModal := views.NewThemeModalView(a.emit)
	portScanModal := views.NewPortScanModalView(a.emit)
	interfacePickerModal := views.NewInterfaceModalView(a.emit)

	a.pages.AddPage(routes.RouteDashboard, dashboardPage, true, false)
	a.pages.AddPage(routes.RouteDetail, detailPage, true, false)
	a.pages.AddPage(routes.RouteSplash, splashPage, true, false)
	a.pages.AddPage(routes.RouteThemePicker, themePickerModal, true, false)
	a.pages.AddPage(routes.RoutePortScan, portScanModal, true, false)
	a.pages.AddPage(routes.RouteInterfacePicker, interfacePickerModal, true, false)

	initialPage := routes.RouteDashboard
	if cfg != nil && cfg.Splash.Enabled {
		initialPage = routes.RouteSplash
	}
	a.pages.SwitchToPage(initialPage)
}

// methods like this can be re-used for other commands
func (a *App) setupEngine(cfg *config.Config, ouiDB *oui.Registry) error {
	iface, err := discovery.NewInterfaceInfo(cfg.NetworkInterface)
	if err != nil {
		return fmt.Errorf("failed to get network interface: %w", err)
	}

	a.portScanner = discovery.NewPortScanner(100, iface)

	a.engine = core.BuildEngine(iface, ouiDB, core.GetEnabledFromCfg(cfg), cfg.ScanDuration)

	a.iface = iface
	a.prober = probe.New(5 * time.Second)

	return nil
}

func (a *App) handleGlobalKeys(event *tcell.EventKey) *tcell.EventKey {
	// if the app isn't fully started, but it can already listen to key events this can cause a UI bug
	if !a.isReady {
		return event
	}
	switch event.Key() {
	case tcell.KeyCtrlT:
		a.emit(events.NavigateTo{Route: routes.RouteThemePicker, Overlay: true})
		return nil
	case tcell.KeyCtrlI:
		// Refresh available interfaces before showing picker
		a.state.SetAvailableInterfaces(discovery.ListAllInterfaces())
		a.emit(events.NavigateTo{Route: routes.RouteInterfacePicker, Overlay: true})
		return nil
	case tcell.KeyCtrlC, tcell.KeyCtrlQ:
		a.Stop()
		return nil
	}

	return event
}

func (a *App) startUIRefreshLoop() {
	a.refreshTicker = time.NewTicker(refreshInterval)

	go func() {
		for range a.refreshTicker.C {
			a.rerenderVisibleViews()
		}
	}()
}

func (a *App) startDiscoveryScanLoop() {
	if a.cfg == nil {
		return
	}

	a.scanTicker = time.NewTicker(a.cfg.ScanInterval)

	go func() {
		a.performScan()

		for range a.scanTicker.C {
			a.performScan()
		}
	}()
}

func (a *App) QueueUpdateDraw(f func()) {
	if a.Application == nil {
		return
	}
	go func() {
		a.Application.QueueUpdateDraw(f)
	}()
}

func (a *App) performScan() {
	if a.cfg == nil || a.engine == nil {
		return
	}

	a.emit(events.DiscoveryStarted{})

	a.scanMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.ScanDuration)
	a.scanCancel = cancel
	a.scanMu.Unlock()

	_, _ = a.engine.Stream(ctx, func(d *discovery.Device) {
		a.state.UpsertDevice(d)
	})
	cancel()

	// Inject local device (self) into the device list
	a.injectLocalDevice()

	a.emit(events.DiscoveryStopped{})
}

// applyTheme applies a theme by name, updates state, applies to primitives, and renders all pages.
func (a *App) applyTheme(name string) {
	a.cfg.Theme.Name = name

	var th tview.Theme
	switch {
	case theme.IsNoColor():
		th = theme.NoColorTheme()
	case !a.cfg.Theme.Enabled:
		th = theme.TviewDefaultTheme()
	default:
		th = theme.Resolve(&a.cfg.Theme)
	}

	tview.Styles = th
	theme.ApplyThemeToAllRegisteredPrimitives()
	a.rerenderVisibleViews()
}

func (a *App) resetFocus() {
	_, item := a.pages.GetFrontPage()
	if item == nil {
		return
	}
	if view, ok := item.(views.View); ok {
		if ft := view.FocusTarget(); ft != nil {
			a.SetFocus(ft)
		} else {
			a.SetFocus(view)
		}
	}
}

func (a *App) rerenderVisibleViews() {
	a.QueueUpdateDraw(func() {
		for _, name := range a.pages.GetPageNames(true) {
			if pageItem := a.pages.GetPage(name); pageItem != nil {
				if view, ok := pageItem.(views.View); ok {
					view.Render(a.state.ReadOnly())
				}
			}
		}
	})
}

func (a *App) handleEvents() {
	for e := range a.events {
		zap.L().Debug("Handling event: ", zap.Any("event", e))
		switch event := e.(type) {
		case events.DeviceSelected:
			a.state.SetSelectedIP(event.IP)
		case events.FilterChanged:
			a.state.SetFilterPattern(event.Pattern)
		case events.NavigateTo:
			if event.Overlay {
				a.pages.SendToFront(event.Route)
				a.pages.ShowPage(event.Route)
			} else {
				a.pages.SwitchToPage(event.Route)
			}
			a.resetFocus()
		case events.ThemeSelected:
			a.applyTheme(event.Name)
			a.state.SetCurrentTheme(event.Name)
		case events.ThemeSaved:
			_ = theme.SaveToConfig(event.Name, a.cfg)
		case events.ThemeConfirmed:
			a.state.SetPreviousTheme(a.state.CurrentTheme())
		case events.HideView:
			front, _ := a.pages.GetFrontPage()
			a.pages.HidePage(front)
			a.resetFocus()
		case events.DiscoveryStarted:
			a.state.SetIsDiscovering(true)
		case events.DiscoveryStopped:
			a.state.SetIsDiscovering(false)
		case events.PortScanStarted:
			a.state.SetIsPortscanning(true)
			a.emit(events.HideView{})
			go a.startPortscan()
		case events.PortScanStopped:
			a.state.SetIsPortscanning(false)
		case events.SearchStarted:
			a.state.SetSearchActive(true)
		case events.SearchError:
			a.state.SetSearchError(event.Error)
		case events.SearchFinished:
			a.state.SetSearchActive(false)
		case events.CopyIP:
			var ip string
			if event.IP != "" {
				ip = event.IP
			} else {
				device, ok := a.state.Selected()
				if ok {
					ip = device.IP.String()
				}
			}
			if ip != "" {
				if err := a.clipboard.CopyText(ip); err != nil {
					zap.L().Warn("failed to copy to clipboard", zap.Error(err))
				}
			}
		case events.InterfaceSelected:
			go a.switchInterface(event.Name)
		case events.ProbeStarted:
			a.state.SetIsProbing(true)
			go a.startProbe()
		case events.ProbeStopped:
			a.state.SetIsProbing(false)
		case events.WoLRequested:
			go a.sendWoL()
		}
		a.rerenderVisibleViews()
	}
}

func (a *App) startPortscan() {
	device, ok := a.state.Selected()
	if !ok {
		a.emit(events.PortScanStopped{})
		return
	}
	ip := device.IP.String()
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.ScanDuration)
	defer cancel()

	device.OpenPorts = map[string][]int{}
	device.LastPortScan = time.Now()

	// todo(ramon) handle errors properly
	var mu sync.Mutex
	_ = a.portScanner.Stream(ctx, ip, a.cfg.PortScanner.TCP, a.cfg.PortScanner.Timeout, func(port int) {
		mu.Lock()
		defer mu.Unlock()
		device.OpenPorts["tcp"] = append(device.OpenPorts["tcp"], port)
		a.state.UpsertDevice(&device)
	})

	a.emit(events.PortScanStopped{})
}

// switchInterface rebuilds the discovery engine for a new network interface,
// cancels any in-progress scan, clears discovered devices, and restarts scanning.
func (a *App) switchInterface(ifaceName string) {
	currentActive := a.state.ActiveInterface()
	if ifaceName == currentActive {
		zap.L().Debug("interface unchanged, skipping switch", zap.String("interface", ifaceName))
		return
	}

	zap.L().Info("switching network interface", zap.String("from", currentActive), zap.String("to", ifaceName))

	// Cancel any in-progress scan
	a.scanMu.Lock()
	if a.scanCancel != nil {
		a.scanCancel()
	}
	a.scanMu.Unlock()

	// Stop scan ticker while rebuilding
	if a.scanTicker != nil {
		a.scanTicker.Stop()
	}

	// Build new interface info
	iface, err := discovery.NewInterfaceInfo(ifaceName)
	if err != nil {
		zap.L().Error("failed to switch interface", zap.String("interface", ifaceName), zap.Error(err))
		return
	}

	// Rebuild engine
	a.engine = core.BuildEngine(iface, a.ouiDB, core.GetEnabledFromCfg(a.cfg), a.cfg.ScanDuration)
	a.portScanner = discovery.NewPortScanner(100, iface)
	a.iface = iface

	// Update state
	a.state.SetActiveInterface(ifaceName)
	if iface.IPv4Addr != nil {
		a.state.SetLocalIP(iface.IPv4Addr.String())
	}
	a.state.ClearDevices()

	// Restart the scan loop
	a.startDiscoveryScanLoop()
}

// startProbe runs all network probes on the currently selected device.
func (a *App) startProbe() {
	device, ok := a.state.Selected()
	if !ok {
		a.emit(events.ProbeStopped{})
		return
	}

	ip := device.IP.String()
	var openPorts []int
	if tcpPorts, ok := device.OpenPorts["tcp"]; ok {
		openPorts = tcpPorts
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := a.prober.RunAll(ctx, ip, device.MAC, device.Manufacturer, openPorts, device.ExtraData)

	// Apply results to device
	device.Latency = result.Latency
	device.ReverseDNS = result.ReverseDNS
	device.Banners = result.Banners
	device.HTTPTitle = result.HTTPTitle
	device.HTTPServer = result.HTTPServer
	device.DeviceType = result.DeviceType
	device.NetBIOSName = result.NetBIOSName
	device.LastProbe = time.Now()

	// Enrich display name from probe results
	if device.DisplayName == "" {
		if result.NetBIOSName != "" {
			device.DisplayName = result.NetBIOSName
		} else if result.ReverseDNS != "" {
			device.DisplayName = result.ReverseDNS
		}
	}

	a.state.UpsertDevice(&device)
	a.emit(events.ProbeStopped{})
}

// sendWoL sends a Wake-on-LAN magic packet to the selected device.
func (a *App) sendWoL() {
	device, ok := a.state.Selected()
	if !ok {
		return
	}
	if device.MAC == "" {
		zap.L().Warn("cannot send WoL: device has no MAC address")
		return
	}
	if a.iface == nil || a.iface.IPv4Net == nil {
		zap.L().Warn("cannot send WoL: no network interface info")
		return
	}

	broadcast := probe.BroadcastAddr(a.iface.IPv4Net)
	if broadcast == nil {
		zap.L().Warn("cannot compute broadcast address")
		return
	}

	if err := probe.SendWoL(device.MAC, broadcast.String()); err != nil {
		zap.L().Error("failed to send WoL", zap.Error(err))
	} else {
		zap.L().Info("WoL packet sent", zap.String("mac", device.MAC), zap.String("broadcast", broadcast.String()))
	}
}

// injectLocalDevice adds the local machine as a device in the discovered list.
func (a *App) injectLocalDevice() {
	if a.iface == nil || a.iface.IPv4Addr == nil {
		return
	}

	localDev := discovery.NewDevice(*a.iface.IPv4Addr)
	localDev.MAC = a.iface.Interface.HardwareAddr.String()
	localDev.DisplayName = "(this device)"
	localDev.Sources["local"] = struct{}{}

	if a.ouiDB != nil {
		localDev.Manufacturer, _ = a.ouiDB.Lookup(localDev.MAC)
	}

	a.state.UpsertDevice(&localDev)
}
