package ui

import "github.com/derailed/tview"

type Pages struct {
	*tview.Pages
}

func NewPages() *Pages {
	p := Pages{
		Pages: tview.NewPages(),
	}

	return &p
}
