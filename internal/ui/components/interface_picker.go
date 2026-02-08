package components

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/ramonvermeulen/whosthere/internal/core/discovery"
	"github.com/ramonvermeulen/whosthere/internal/core/state"
	"github.com/ramonvermeulen/whosthere/internal/ui/events"
	"github.com/ramonvermeulen/whosthere/internal/ui/theme"
	"github.com/rivo/tview"
)

var _ UIComponent = &InterfacePicker{}

// InterfacePicker is a component for selecting a network interface.
type InterfacePicker struct {
	*tview.List
	interfaces []discovery.InterfaceEntry
	emit       func(events.Event)
}

// NewInterfacePicker creates a new interface picker list component.
func NewInterfacePicker(emit func(events.Event)) *InterfacePicker {
	list := tview.NewList()
	list.ShowSecondaryText(true)

	ip := &InterfacePicker{
		List: list,
		emit: emit,
	}

	theme.RegisterPrimitive(list)

	return ip
}

// setupInputHandling configures vim-style navigation.
func (ip *InterfacePicker) setupInputHandling() {
	ip.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch {
		case event.Rune() == 'j' || event.Key() == tcell.KeyDown:
			nextIdx := ip.GetCurrentItem() + 1
			if nextIdx < len(ip.interfaces) {
				ip.SetCurrentItem(nextIdx)
			}
			return nil
		case event.Rune() == 'k' || event.Key() == tcell.KeyUp:
			prevIdx := ip.GetCurrentItem() - 1
			if prevIdx >= 0 {
				ip.SetCurrentItem(prevIdx)
			}
			return nil
		case event.Key() == tcell.KeyEnter:
			currentIdx := ip.GetCurrentItem()
			if currentIdx >= 0 && currentIdx < len(ip.interfaces) {
				ip.emit(events.InterfaceSelected{Name: ip.interfaces[currentIdx].Name})
				ip.emit(events.HideView{})
			}
			return nil
		case event.Key() == tcell.KeyEsc || event.Rune() == 'q':
			ip.emit(events.HideView{})
			return nil
		}
		return event
	})
}

// Render implements UIComponent.
func (ip *InterfacePicker) Render(s state.ReadOnly) {
	ip.Clear()
	ip.interfaces = s.AvailableInterfaces()
	activeIface := s.ActiveInterface()

	ip.SetBorder(true).
		SetTitle(fmt.Sprintf(" Network Interface (%d) ", len(ip.interfaces))).
		SetTitleAlign(tview.AlignCenter).
		SetTitleColor(tview.Styles.TitleColor).
		SetBorderColor(tview.Styles.BorderColor).
		SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)

	var currentIndex int

	for i, iface := range ip.interfaces {
		displayName := iface.Name
		if iface.Name == activeIface {
			displayName = "✓ " + displayName
			currentIndex = i
		}
		if iface.IsVPN {
			displayName += " [VPN/TUN]"
		}

		secondaryText := fmt.Sprintf("  %s  %s  %s", iface.IPv4, iface.Subnet, iface.Flags)
		if iface.MAC != "" {
			secondaryText += "  " + iface.MAC
		}

		name := iface.Name
		ip.AddItem(displayName, secondaryText, 0, func() {
			ip.emit(events.InterfaceSelected{Name: name})
			ip.emit(events.HideView{})
		})
	}

	ip.SetCurrentItem(currentIndex)
	ip.setupInputHandling()
}
