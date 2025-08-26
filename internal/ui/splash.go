package ui

import (
	"fmt"
	"strings"

	"github.com/derailed/tview"
)

var LogoBig = []string{
	`Knock Knock..                                                     `,
	`                _               _   _                   ___       `,
	`      __      _| |__   ___  ___| |_| |__   ___ _ __ ___/ _ \      `,
	`      \ \ /\ / / '_ \ / _ \/ __| __| '_ \ / _ \ '__/ _ \// /      `,
	`       \ V  V /| | | | (_) \__ \ |_| | | |  __/ | |  __/ \/       `,
	`        \_/\_/ |_| |_|\___/|___/\__|_| |_|\___|_|  \___| ()       `,
}

type Splash struct {
	*tview.Flex
}

func NewSplash() *Splash {
	s := Splash{Flex: tview.NewFlex()}

	logo := tview.NewTextView()
	logo.SetDynamicColors(true)
	logo.SetTextAlign(tview.AlignCenter)

	// TODO(ramon): fix styles via injectable style configuration
	logoText := strings.Join(LogoBig, "\n[green::b]")
	_, _ = fmt.Fprintf(logo, "%s[green::b]%s\n",
		strings.Repeat("\n", 2),
		logoText)

	s.AddItem(logo, 0, 1, false)

	return &s
}
