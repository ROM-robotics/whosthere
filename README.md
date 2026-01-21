# whosthere

[![Go Report Card](https://goreportcard.com/badge/github.com/ramonvermeulen/whosthere)](https://goreportcard.com/report/github.com/ramonvermeulen/whosthere) [![Go Version](https://img.shields.io/github/go-mod/go-version/ramonvermeulen/whosthere)](https://go.dev/doc/devel/release) [![License](https://img.shields.io/github/license/ramonvermeulen/whosthere)](LICENSE)

Local network discovery tool with a modern Terminal User Interface (TUI) written in Go.
Discover, explore, and understand your Local Area Network in an intuitive way. It performs
**privilege-less, concurrent scans** using ARP, multicast DNS, and TCP/UDP connections to
quickly find and identify devices on your Local Area Network.

## Features

- **Modern TUI:** Navigate and explore discovered devices intuitively.
- **Fast & Concurrent:** Leverages multiple discovery methods simultaneously.
- **No Elevated Privileges Required:** Runs entirely in user-space.
- **Device Enrichment:** Uses [**OUI**](https://standards-oui.ieee.org/) lookup to show device manufacturers.
- **Integrated Port Scanner:** Optional service discovery on found hosts.
- **Pluggable Architecture:** Extensible with custom scanners.
- **Daemon Mode with HTTP API:** Run in the background and integrate with other tools.
- **Theming & Configuration:** Personalize the look and behavior via YAML configuration.

Knock knock.. Who's there? 🚪

![demo gif](<>)

## Installation

```bash
brew tap ramonvermeulen/whosthere
brew install whosthere
```

Or with Go:

```bash
go install github.com/ramonvermeulen/whosthere@latest
```

Or build from source:

```bash
git clone github.com/ramonvermeulen/whosthere.git
cd whosthere
make build
```

## Usage

Run the TUI for interactive discovery:

```bash
whosthere
```

Run as a daemon with HTTP API:

```bash
whosthere daemon --port 8080
```

Additional command line options can be found by running:

```bash
whosthere --help
```

## Key bindings (TUI)

| Key                | Action                    |
| ------------------ | ------------------------- |
| `/`                | Start regex search        |
| `k`                | Up                        |
| `j`                | Down                      |
| `g`                | Go to top                 |
| `G`                | Go to bottom              |
| `enter`            | Show device details       |
| `CTRL+t`           | Toggle theme selector     |
| `CTRL+c`           | Stop application          |
| `ESC`              | Clear search / Go back    |
| `p` (details view) | Start port scan on device |
| `tab` (modal view) | Switch button selection   |

## Environment Variables

| Variable           | Description                                                                                                                                                                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WHOSTHERE_CONFIG` | Path to the configuration file. Defaults to `$XDG_CONFIG_HOME/whosthere/config.yaml` or `~/.config/whosthere/config.yaml` if the [**XDG Base Directory**](https://specifications.freedesktop.org/basedir/latest/#basics) environment variables are not set. |
| `WHOSTHERE_LOG`    | Set the log level (e.g., `debug`, `info`, `warn`, `error`). Defaults to `info`.                                                                                                                                                                             |

## Configuration

```yaml
# How often to run discovery scans
scan_interval: 10s

# Maximum duration for each scan
scan_duration: 5s

# Splash screen configuration
splash:
  enabled: true
  delay: 1s

# Theme configuration
theme:
  # Configure the theme to use for the TUI, complete list of available themes at:
  # https://github.com/ramonvermeulen/whosthere/tree/main/internal/ui/theme/theme.go
  # Set name to "custom" to use the custom colors below
  # For any color that is not configured it will take the default theme value as fallback
  name: default

  # Custom theme colors (uncomment and set name: custom to use)
  # primitive_background_color: "#000a1a"
  # contrast_background_color: "#001a33"
  # more_contrast_background_color: "#003366"
  # border_color: "#0088ff"
  # title_color: "#00ffff"
  # graphics_color: "#00ffaa"
  # primary_text_color: "#cceeff"
  # secondary_text_color: "#6699ff"
  # tertiary_text_color: "#ffaa00"
  # inverse_text_color: "#000a1a"
  # contrast_secondary_text_color: "#88ddff"

# Scanner configuration
scanners:
  mdns:
    enabled: true
  ssdp:
    enabled: true
  arp:
    enabled: true

# Port scanner configuration
port_scanner:
  timeout: 5s
  tcp: [21, 22, 23, 25, 80, 110, 135, 139, 143, 389, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9000, 9090, 9200, 9300, 10000, 27017]

# Uncomment the next line to configure a specific network interface - uses OS default if not set
# network_interface: lo0
```

## Logging

Logs are written to `$XDG_STATE_HOME/whosthere/app.log` or `~/.local/state/whosthere/app.log` if the 
[**XDG Base Directory**](https://specifications.freedesktop.org/basedir/latest/#basics) environment variables 
are not set. When not running in TUI mode, logs are also written to standard output.
