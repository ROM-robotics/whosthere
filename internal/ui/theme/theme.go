package theme

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/ramonvermeulen/whosthere/internal/core/config"
	"github.com/ramonvermeulen/whosthere/internal/core/logging"
	"github.com/rivo/tview"
	"go.uber.org/zap"
)

var registry = map[string]tview.Theme{
	config.DefaultThemeName: {
		PrimitiveBackgroundColor:    tcell.GetColor("#000a1a"),
		ContrastBackgroundColor:     tcell.GetColor("#001a33"),
		MoreContrastBackgroundColor: tcell.GetColor("#003366"),
		BorderColor:                 tcell.GetColor("#0088ff"),
		TitleColor:                  tcell.GetColor("#00ffff"),
		GraphicsColor:               tcell.GetColor("#00ffaa"),
		PrimaryTextColor:            tcell.GetColor("#cceeff"),
		SecondaryTextColor:          tcell.GetColor("#6699ff"),
		TertiaryTextColor:           tcell.GetColor("#ffaa00"),
		InverseTextColor:            tcell.GetColor("#000a1a"),
		ContrastSecondaryTextColor:  tcell.GetColor("#88ddff"),
	},

	"dracula": {
		PrimitiveBackgroundColor:    tcell.GetColor("#282a36"),
		ContrastBackgroundColor:     tcell.GetColor("#44475a"),
		MoreContrastBackgroundColor: tcell.GetColor("#6272a4"),
		BorderColor:                 tcell.GetColor("#bd93f9"),
		TitleColor:                  tcell.GetColor("#8be9fd"),
		GraphicsColor:               tcell.GetColor("#ff79c6"),
		PrimaryTextColor:            tcell.GetColor("#f8f8f2"),
		SecondaryTextColor:          tcell.GetColor("#bd93f9"),
		TertiaryTextColor:           tcell.GetColor("#ffb86c"),
		InverseTextColor:            tcell.GetColor("#44475a"),
		ContrastSecondaryTextColor:  tcell.GetColor("#50fa7b"),
	},

	"nord": {
		PrimitiveBackgroundColor:    tcell.GetColor("#2e3440"),
		ContrastBackgroundColor:     tcell.GetColor("#3b4252"),
		MoreContrastBackgroundColor: tcell.GetColor("#434c5e"),
		BorderColor:                 tcell.GetColor("#81a1c1"),
		TitleColor:                  tcell.GetColor("#88c0d0"),
		GraphicsColor:               tcell.GetColor("#bf616a"),
		PrimaryTextColor:            tcell.GetColor("#d8dee9"),
		SecondaryTextColor:          tcell.GetColor("#81a1c1"),
		TertiaryTextColor:           tcell.GetColor("#ebcb8b"),
		InverseTextColor:            tcell.GetColor("#4c566a"),
		ContrastSecondaryTextColor:  tcell.GetColor("#a3be8c"),
	},

	"solarized-dark": {
		PrimitiveBackgroundColor:    tcell.GetColor("#002b36"),
		ContrastBackgroundColor:     tcell.GetColor("#073642"),
		MoreContrastBackgroundColor: tcell.GetColor("#586e75"),
		BorderColor:                 tcell.GetColor("#268bd2"),
		TitleColor:                  tcell.GetColor("#2aa198"),
		GraphicsColor:               tcell.GetColor("#d33682"),
		PrimaryTextColor:            tcell.GetColor("#839496"),
		SecondaryTextColor:          tcell.GetColor("#268bd2"),
		TertiaryTextColor:           tcell.GetColor("#b58900"),
		InverseTextColor:            tcell.GetColor("#fdf6e3"),
		ContrastSecondaryTextColor:  tcell.GetColor("#859900"),
	},

	"solarized-light": {
		PrimitiveBackgroundColor:    tcell.GetColor("#fdf6e3"),
		ContrastBackgroundColor:     tcell.GetColor("#eee8d5"),
		MoreContrastBackgroundColor: tcell.GetColor("#93a1a1"),
		BorderColor:                 tcell.GetColor("#268bd2"),
		TitleColor:                  tcell.GetColor("#2aa198"),
		GraphicsColor:               tcell.GetColor("#d33682"),
		PrimaryTextColor:            tcell.GetColor("#657b83"),
		SecondaryTextColor:          tcell.GetColor("#268bd2"),
		TertiaryTextColor:           tcell.GetColor("#b58900"),
		InverseTextColor:            tcell.GetColor("#002b36"),
		ContrastSecondaryTextColor:  tcell.GetColor("#859900"),
	},

	"gruvbox-dark": {
		PrimitiveBackgroundColor:    tcell.GetColor("#282828"),
		ContrastBackgroundColor:     tcell.GetColor("#3c3836"),
		MoreContrastBackgroundColor: tcell.GetColor("#504945"),
		BorderColor:                 tcell.GetColor("#d65d0e"),
		TitleColor:                  tcell.GetColor("#689d6a"),
		GraphicsColor:               tcell.GetColor("#cc241d"),
		PrimaryTextColor:            tcell.GetColor("#ebdbb2"),
		SecondaryTextColor:          tcell.GetColor("#fe8019"),
		TertiaryTextColor:           tcell.GetColor("#fabd2f"),
		InverseTextColor:            tcell.GetColor("#3c3836"),
		ContrastSecondaryTextColor:  tcell.GetColor("#b8bb26"),
	},

	"onedark": {
		PrimitiveBackgroundColor:    tcell.GetColor("#282c34"),
		ContrastBackgroundColor:     tcell.GetColor("#2c323c"),
		MoreContrastBackgroundColor: tcell.GetColor("#3e4452"),
		BorderColor:                 tcell.GetColor("#61afef"),
		TitleColor:                  tcell.GetColor("#56b6c2"),
		GraphicsColor:               tcell.GetColor("#e06c75"),
		PrimaryTextColor:            tcell.GetColor("#abb2bf"),
		SecondaryTextColor:          tcell.GetColor("#61afef"),
		TertiaryTextColor:           tcell.GetColor("#d19a66"),
		InverseTextColor:            tcell.GetColor("#3e4452"),
		ContrastSecondaryTextColor:  tcell.GetColor("#98c379"),
	},

	"tokyonight": {
		PrimitiveBackgroundColor:    tcell.GetColor("#1a1b26"),
		ContrastBackgroundColor:     tcell.GetColor("#24283b"),
		MoreContrastBackgroundColor: tcell.GetColor("#414868"),
		BorderColor:                 tcell.GetColor("#7aa2f7"),
		TitleColor:                  tcell.GetColor("#2ac3de"),
		GraphicsColor:               tcell.GetColor("#f7768e"),
		PrimaryTextColor:            tcell.GetColor("#c0caf5"),
		SecondaryTextColor:          tcell.GetColor("#7aa2f7"),
		TertiaryTextColor:           tcell.GetColor("#e0af68"),
		InverseTextColor:            tcell.GetColor("#414868"),
		ContrastSecondaryTextColor:  tcell.GetColor("#9ece6a"),
	},

	"catppuccin-mocha": {
		PrimitiveBackgroundColor:    tcell.GetColor("#1e1e2e"),
		ContrastBackgroundColor:     tcell.GetColor("#313244"),
		MoreContrastBackgroundColor: tcell.GetColor("#45475a"),
		BorderColor:                 tcell.GetColor("#89b4fa"),
		TitleColor:                  tcell.GetColor("#89dceb"),
		GraphicsColor:               tcell.GetColor("#f38ba8"),
		PrimaryTextColor:            tcell.GetColor("#cdd6f4"),
		SecondaryTextColor:          tcell.GetColor("#b4befe"),
		TertiaryTextColor:           tcell.GetColor("#f9e2af"),
		InverseTextColor:            tcell.GetColor("#313244"),
		ContrastSecondaryTextColor:  tcell.GetColor("#a6e3a1"),
	},

	"rose-pine": {
		PrimitiveBackgroundColor:    tcell.GetColor("#191724"),
		ContrastBackgroundColor:     tcell.GetColor("#1f1d2e"),
		MoreContrastBackgroundColor: tcell.GetColor("#26233a"),
		BorderColor:                 tcell.GetColor("#31748f"),
		TitleColor:                  tcell.GetColor("#9ccfd8"),
		GraphicsColor:               tcell.GetColor("#eb6f92"),
		PrimaryTextColor:            tcell.GetColor("#e0def4"),
		SecondaryTextColor:          tcell.GetColor("#c4a7e7"),
		TertiaryTextColor:           tcell.GetColor("#f6c177"),
		InverseTextColor:            tcell.GetColor("#1f1d2e"),
		ContrastSecondaryTextColor:  tcell.GetColor("#9ccfd8"),
	},

	"monokai": {
		PrimitiveBackgroundColor:    tcell.GetColor("#272822"),
		ContrastBackgroundColor:     tcell.GetColor("#3e3d32"),
		MoreContrastBackgroundColor: tcell.GetColor("#75715e"),
		BorderColor:                 tcell.GetColor("#66d9ef"),
		TitleColor:                  tcell.GetColor("#a6e22e"),
		GraphicsColor:               tcell.GetColor("#f92672"),
		PrimaryTextColor:            tcell.GetColor("#f8f8f2"),
		SecondaryTextColor:          tcell.GetColor("#fd971f"),
		TertiaryTextColor:           tcell.GetColor("#ae81ff"),
		InverseTextColor:            tcell.GetColor("#3e3d32"),
		ContrastSecondaryTextColor:  tcell.GetColor("#a6e22e"),
	},

	"material": {
		PrimitiveBackgroundColor:    tcell.GetColor("#263238"),
		ContrastBackgroundColor:     tcell.GetColor("#37474f"),
		MoreContrastBackgroundColor: tcell.GetColor("#546e7a"),
		BorderColor:                 tcell.GetColor("#82b1ff"),
		TitleColor:                  tcell.GetColor("#80deea"),
		GraphicsColor:               tcell.GetColor("#ff5252"),
		PrimaryTextColor:            tcell.GetColor("#cfd8dc"),
		SecondaryTextColor:          tcell.GetColor("#b388ff"),
		TertiaryTextColor:           tcell.GetColor("#ffd740"),
		InverseTextColor:            tcell.GetColor("#37474f"),
		ContrastSecondaryTextColor:  tcell.GetColor("#69f0ae"),
	},

	"high-contrast": {
		PrimitiveBackgroundColor:    tcell.GetColor("#000000"),
		ContrastBackgroundColor:     tcell.GetColor("#0a0a0a"),
		MoreContrastBackgroundColor: tcell.GetColor("#1a1a1a"),
		BorderColor:                 tcell.GetColor("#00ffff"),
		TitleColor:                  tcell.GetColor("#ffff00"),
		GraphicsColor:               tcell.GetColor("#ff00ff"),
		PrimaryTextColor:            tcell.GetColor("#ffffff"),
		SecondaryTextColor:          tcell.GetColor("#00ffff"),
		TertiaryTextColor:           tcell.GetColor("#ffff00"),
		InverseTextColor:            tcell.GetColor("#ffffff"),
		ContrastSecondaryTextColor:  tcell.GetColor("#00ff00"),
	},

	"papercolor-light": {
		PrimitiveBackgroundColor:    tcell.GetColor("#eeeeee"),
		ContrastBackgroundColor:     tcell.GetColor("#afafaf"),
		MoreContrastBackgroundColor: tcell.GetColor("#878787"),
		BorderColor:                 tcell.GetColor("#0087af"),
		TitleColor:                  tcell.GetColor("#00afaf"),
		GraphicsColor:               tcell.GetColor("#d7005f"),
		PrimaryTextColor:            tcell.GetColor("#444444"),
		SecondaryTextColor:          tcell.GetColor("#005f87"),
		TertiaryTextColor:           tcell.GetColor("#d75f00"),
		InverseTextColor:            tcell.GetColor("#eeeeee"),
		ContrastSecondaryTextColor:  tcell.GetColor("#00af87"),
	},

	"ayu-dark": {
		PrimitiveBackgroundColor:    tcell.GetColor("#0a0e14"),
		ContrastBackgroundColor:     tcell.GetColor("#0f1419"),
		MoreContrastBackgroundColor: tcell.GetColor("#1a1f29"),
		BorderColor:                 tcell.GetColor("#39bae6"),
		TitleColor:                  tcell.GetColor("#95e6cb"),
		GraphicsColor:               tcell.GetColor("#ff3333"),
		PrimaryTextColor:            tcell.GetColor("#b3b1ad"),
		SecondaryTextColor:          tcell.GetColor("#59c2ff"),
		TertiaryTextColor:           tcell.GetColor("#ffb454"),
		InverseTextColor:            tcell.GetColor("#1a1f29"),
		ContrastSecondaryTextColor:  tcell.GetColor("#c2d94c"),
	},

	"everforest": {
		PrimitiveBackgroundColor:    tcell.GetColor("#2b3339"),
		ContrastBackgroundColor:     tcell.GetColor("#3c474d"),
		MoreContrastBackgroundColor: tcell.GetColor("#4b565c"),
		BorderColor:                 tcell.GetColor("#7fbbb3"),
		TitleColor:                  tcell.GetColor("#83c092"),
		GraphicsColor:               tcell.GetColor("#e67e80"),
		PrimaryTextColor:            tcell.GetColor("#d3c6aa"),
		SecondaryTextColor:          tcell.GetColor("#a7c080"),
		TertiaryTextColor:           tcell.GetColor("#dbbc7f"),
		InverseTextColor:            tcell.GetColor("#3c474d"),
		ContrastSecondaryTextColor:  tcell.GetColor("#83c092"),
	},
}

// Resolve returns the theme by name. Unknown names fall back to default; "custom" applies overrides atop default.
func Resolve(tc *config.ThemeConfig) tview.Theme {
	name := strings.ToLower(strings.TrimSpace(config.DefaultThemeName))
	if tc != nil {
		if n := strings.TrimSpace(tc.Name); n != "" {
			name = strings.ToLower(n)
		}
	}

	base, ok := registry[name]
	if name == config.CustomThemeName {
		defaultTheme := registry[config.DefaultThemeName]
		base = applyOverrides(&defaultTheme, tc)
	} else if !ok {
		logging.L().Warn("theme not found, falling back to default", zap.String("name", name))
		base = registry[config.DefaultThemeName]
	}

	tview.Styles = base
	return base
}

// applyOverrides starts from base and applies overrides from config.
func applyOverrides(base *tview.Theme, tc *config.ThemeConfig) tview.Theme {
	if base == nil {
		return registry[config.DefaultThemeName]
	}

	th := *base
	if tc == nil {
		return th
	}

	if c := parseColor(tc.PrimitiveBackgroundColor); c != nil {
		th.PrimitiveBackgroundColor = *c
	}
	if c := parseColor(tc.ContrastBackgroundColor); c != nil {
		th.ContrastBackgroundColor = *c
	}
	if c := parseColor(tc.MoreContrastBackgroundColor); c != nil {
		th.MoreContrastBackgroundColor = *c
	}
	if c := parseColor(tc.BorderColor); c != nil {
		th.BorderColor = *c
	}
	if c := parseColor(tc.TitleColor); c != nil {
		th.TitleColor = *c
	}
	if c := parseColor(tc.GraphicsColor); c != nil {
		th.GraphicsColor = *c
	}
	if c := parseColor(tc.PrimaryTextColor); c != nil {
		th.PrimaryTextColor = *c
	}
	if c := parseColor(tc.SecondaryTextColor); c != nil {
		th.SecondaryTextColor = *c
	}
	if c := parseColor(tc.TertiaryTextColor); c != nil {
		th.TertiaryTextColor = *c
	}
	if c := parseColor(tc.InverseTextColor); c != nil {
		th.InverseTextColor = *c
	}
	if c := parseColor(tc.ContrastSecondaryTextColor); c != nil {
		th.ContrastSecondaryTextColor = *c
	}

	return th
}

// helper to transform user defined color strings into tcell.Color pointers.
func parseColor(s string) *tcell.Color {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	c := tcell.GetColor(s)
	return &c
}

// Names returns the currently registered theme names (built-ins plus any custom registrations).
func Names() []string {
	names := make([]string, 0, len(registry))
	for k := range registry {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// Get retrieves a theme by name from the registry. Falls back to default if not found.
func Get(name string) tview.Theme {
	name = strings.ToLower(strings.TrimSpace(name))
	th, ok := registry[name]
	if !ok {
		logging.L().Warn("theme not found, falling back to default", zap.String("name", name))
		th = registry[config.DefaultThemeName]
	}
	return th
}

var registerFunc func(tview.Primitive)

// SetRegisterFunc sets the function to call for registering primitives for theme updates.
func SetRegisterFunc(fn func(tview.Primitive)) {
	registerFunc = fn
}

// RegisterPrimitive registers a primitive for theme updates.
func RegisterPrimitive(p tview.Primitive) {
	if registerFunc != nil {
		registerFunc(p)
	}
}

// SaveToConfig saves the current theme to the config file.
func SaveToConfig(themeName string, cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("config not initialized")
	}

	cfg.Theme.Name = themeName

	if err := config.Save(cfg, ""); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	return nil
}

// ApplyToPrimitive applies theme colors to any tview primitive.
// Supports all official tview primitives with proper styling methods.
func ApplyToPrimitive(p tview.Primitive) {
	if p == nil {
		return
	}

	switch v := p.(type) {
	case *tview.TextView:
		v.SetTextColor(tview.Styles.PrimaryTextColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.TextArea:
		v.SetTextStyle(tcell.StyleDefault.
			Foreground(tview.Styles.PrimaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Table:
		v.SetBordersColor(tview.Styles.BorderColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.TreeView:
		v.SetGraphicsColor(tview.Styles.GraphicsColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.List:
		v.SetMainTextStyle(tcell.StyleDefault.
			Foreground(tview.Styles.PrimaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))
		v.SetSecondaryTextStyle(tcell.StyleDefault.
			Foreground(tview.Styles.SecondaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))
		v.SetShortcutStyle(tcell.StyleDefault.
			Foreground(tview.Styles.TertiaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))
		v.SetSelectedStyle(tcell.StyleDefault.
			Foreground(tview.Styles.InverseTextColor).
			Background(tview.Styles.SecondaryTextColor))
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.InputField:
		v.SetFieldTextColor(tview.Styles.PrimaryTextColor)
		v.SetFieldBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetLabelColor(tview.Styles.SecondaryTextColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.DropDown:
		v.SetFieldTextColor(tview.Styles.PrimaryTextColor)
		v.SetFieldBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetLabelColor(tview.Styles.SecondaryTextColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Checkbox:
		v.SetLabelColor(tview.Styles.SecondaryTextColor)
		v.SetFieldTextColor(tview.Styles.PrimaryTextColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Image:
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Button:
		v.SetLabelColor(tview.Styles.PrimaryTextColor)
		v.SetBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Form:
		v.SetFieldBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetFieldTextColor(tview.Styles.PrimaryTextColor)
		v.SetLabelColor(tview.Styles.SecondaryTextColor)
		v.SetButtonBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetButtonTextColor(tview.Styles.PrimaryTextColor)
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Modal:
		v.SetTextColor(tview.Styles.PrimaryTextColor)
		v.SetButtonStyle(tcell.StyleDefault.
			Foreground(tview.Styles.PrimaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))
		v.SetButtonTextColor(tview.Styles.PrimaryTextColor)
		v.SetBackgroundColor(tview.Styles.ContrastBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetBorderStyle(tcell.StyleDefault.
			Foreground(tview.Styles.PrimaryTextColor).
			Background(tview.Styles.PrimitiveBackgroundColor))

	case *tview.Grid:
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBordersColor(tview.Styles.BorderColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Flex:
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	case *tview.Pages:
		v.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		v.SetBorderColor(tview.Styles.BorderColor)
		v.SetTitleColor(tview.Styles.TitleColor)

	default:
		if box, ok := p.(interface{ SetBackgroundColor(tcell.Color) *tview.Box }); ok {
			box.SetBackgroundColor(tview.Styles.PrimitiveBackgroundColor)
		}
		if bordered, ok := p.(interface{ SetBorderColor(tcell.Color) *tview.Box }); ok {
			bordered.SetBorderColor(tview.Styles.BorderColor)
		}
		if titled, ok := p.(interface{ SetTitleColor(tcell.Color) *tview.Box }); ok {
			titled.SetTitleColor(tview.Styles.TitleColor)
		}
	}
}
