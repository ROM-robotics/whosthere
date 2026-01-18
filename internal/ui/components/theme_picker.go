package components

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/ramonvermeulen/whosthere/internal/core/state"
	"github.com/ramonvermeulen/whosthere/internal/ui/events"
	"github.com/ramonvermeulen/whosthere/internal/ui/theme"
	"github.com/rivo/tview"
)

var _ UIComponent = &ThemePicker{}

// ThemePicker is a component for selecting and previewing themes.
// It's just a themed list that handles theme selection logic.
type ThemePicker struct {
	*tview.List
	themes        []string
	previousTheme string
	emit          func(events.Event)
}

// NewThemePicker creates a new theme picker list component.
func NewThemePicker(emit func(events.Event)) *ThemePicker {
	list := tview.NewList()
	list.ShowSecondaryText(false)

	tp := &ThemePicker{
		List:   list,
		themes: theme.Names(),
		emit:   emit,
	}

	theme.RegisterPrimitive(list)

	return tp
}

// setupInputHandling configures vim-style navigation.
func (tp *ThemePicker) setupInputHandling() {
	tp.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch {
		case event.Rune() == 'j' || event.Key() == tcell.KeyDown:
			nextIdx := tp.GetCurrentItem() + 1
			if nextIdx < len(tp.themes) {
				tp.SetCurrentItem(nextIdx)
				tp.emit(events.ThemeSelected{Name: tp.themes[nextIdx]})
			}
			return nil
		case event.Rune() == 'k' || event.Key() == tcell.KeyUp:
			prevIdx := tp.GetCurrentItem() - 1
			if prevIdx >= 0 {
				tp.SetCurrentItem(prevIdx)
				tp.emit(events.ThemeSelected{Name: tp.themes[prevIdx]})
			}
			return nil
		case event.Key() == tcell.KeyEnter && event.Modifiers()&tcell.ModShift != 0:
			currentIdx := tp.GetCurrentItem()
			if currentIdx >= 0 && currentIdx < len(tp.themes) {
				tp.emit(events.ThemeSaved{Name: tp.themes[currentIdx]})
				tp.emit(events.ThemeConfirmed{})
				tp.emit(events.HideView{})
			}
			return nil
		case event.Key() == tcell.KeyEnter:
			tp.emit(events.ThemeConfirmed{})
			tp.emit(events.HideView{})
			return nil
		case event.Key() == tcell.KeyEsc || event.Rune() == 'q':
			tp.emit(events.ThemeSelected{Name: tp.previousTheme})
			tp.emit(events.HideView{})
			return nil
		}
		return event
	})
}

// Render implements UIComponent.
func (tp *ThemePicker) Render(s state.ReadOnly) {
	tp.Clear()
	tp.SetBorder(true).
		SetTitle(fmt.Sprintf(" Theme Picker (%v) ", len(tp.themes))).
		SetTitleAlign(tview.AlignCenter).
		SetTitleColor(tview.Styles.TitleColor).
		SetBorderColor(tview.Styles.BorderColor).
		SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
	tp.ShowSecondaryText(false)

	currentTheme := s.CurrentTheme()
	tp.previousTheme = s.PreviousTheme()
	var currentIndex = 0

	for i, themeName := range tp.themes {
		displayName := themeName
		if themeName == "custom" {
			displayName = "custom (apply overrides from config)"
		}
		if themeName == currentTheme {
			displayName = "✓ " + displayName
			currentIndex = i
		}
		name := themeName
		tp.AddItem(displayName, "", 0, func() {
			tp.emit(events.ThemeSaved{Name: name})
		})
	}

	tp.SetCurrentItem(currentIndex)
	tp.setupInputHandling()
}
