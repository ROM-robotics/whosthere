package views

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/ramonvermeulen/whosthere/internal/core/state"
	"github.com/ramonvermeulen/whosthere/internal/ui/events"
	"github.com/ramonvermeulen/whosthere/internal/ui/theme"
	"github.com/rivo/tview"
)

var _ View = &PortScanModalView{}

// PortScanModalView is a modal overlay page for port scanning the selected device.
type PortScanModalView struct {
	*tview.Modal
	emit func(events.Event)
}

// Common ports to scan
var commonPorts = []int{22, 80, 443, 3389, 8080}

func NewPortScanModalView(emit func(events.Event)) *PortScanModalView {
	modal := tview.NewModal().
		SetText("").
		AddButtons([]string{"Start Scan", "Cancel"}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonIndex == 0 {
				emit(events.PortScanStarted{})
			} else {
				emit(events.HideView{})
			}
		})

	p := &PortScanModalView{
		Modal: modal,
		emit:  emit,
	}

	modal.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEsc {
			emit(events.HideView{})
			return nil
		}
		return event
	})

	theme.RegisterPrimitive(modal)

	return p
}

func (p *PortScanModalView) FocusTarget() tview.Primitive { return p.Modal }

func (p *PortScanModalView) Render(s state.ReadOnly) {
	device, ok := s.Selected()
	if !ok {
		p.Modal.SetText("No device selected.")
		return
	}
	cfg := s.Config()
	udpPorts := cfg.PortScanner.UDP
	tcpPorts := cfg.PortScanner.TCP

	text := fmt.Sprint("The following ports will be scanned:\n\n")
	text += fmt.Sprintf("UDP: %v\n\n", udpPorts)
	text += fmt.Sprintf("TCP: %v", tcpPorts)

	p.Modal.SetText(text).SetTitle(fmt.Sprintf(" IP: %s ", device.IP))
}
