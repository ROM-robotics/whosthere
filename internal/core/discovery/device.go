package discovery

import (
	"net"
	"time"
)

// TODO(ramon): Maybe it could be nice to have a merge strategy? E.g. when multiple scanners return the same device.
// Per column we could for example choose to have a specific Merge strategy, so that the "best" data from different
// scanners could be combined into a single device representation.
// maybe something like?:
// const (
//    MergeFirstWins     MergeStrategy = iota   // First scanner's value wins
//    MergeMostSpecific                         // More specific value wins
//    MergeLongest                              // Longer value (usually more complete)
//    MergeUnion                                // Combine arrays/maps
//    MergeMostRecent                           // Newer timestamp wins
// )
// END TODO

// Device represents a discovered network device aggregated from multiple scanners.
type Device struct {
	IP           net.IP              `json:"ip"`           // Primary IP address (identity key)
	MAC          string              `json:"mac"`          // MAC address of the device
	DisplayName  string              `json:"displayName"`  // Most user-friendly name discovered
	Manufacturer string              `json:"manufacturer"` // Vendor from OUI table
	Services     map[string]int      `json:"services"`     // service name -> port (or 0 if unknown)
	Sources      map[string]struct{} `json:"sources"`      // set of scanners that contributed info
	FirstSeen    time.Time           `json:"firstSeen"`    // first time any scanner saw the device
	LastSeen     time.Time           `json:"lastSeen"`     // last time any scanner saw the device
	ExtraData    map[string]string   `json:"extraData"`    // additional key/value metadata discovered from protocols
	OpenPorts    map[string][]int    `json:"-"`            // protocol -> list of open ports
	LastPortScan time.Time           `json:"-"`            // last time port scan was performed
}

// NewDevice builds a Device with initialized maps and current timestamp as first/last seen.
func NewDevice(ip net.IP) Device {
	now := time.Now()
	return Device{IP: ip, Services: map[string]int{}, Sources: map[string]struct{}{}, FirstSeen: now, LastSeen: now, ExtraData: map[string]string{}, OpenPorts: map[string][]int{}}
}

// Merge merges fields into an existing Device
func (d *Device) Merge(other *Device) {
	// todo allow for more advanced merge strategies per field?
	if other == nil {
		return
	}
	if d.IP == nil && other.IP != nil {
		d.IP = other.IP
	}
	if d.MAC == "" && other.MAC != "" {
		d.MAC = other.MAC
	}
	if d.DisplayName == "" && other.DisplayName != "" {
		d.DisplayName = other.DisplayName
	}
	if d.Manufacturer == "" && other.Manufacturer != "" {
		d.Manufacturer = other.Manufacturer
	}
	if d.Services == nil {
		d.Services = map[string]int{}
	}
	for name, port := range other.Services {
		if _, ok := d.Services[name]; !ok || d.Services[name] == 0 {
			if d.Services[name] == 0 || port != 0 {
				d.Services[name] = port
			}
		}
	}
	if d.Sources == nil {
		d.Sources = map[string]struct{}{}
	}
	for src := range other.Sources {
		d.Sources[src] = struct{}{}
	}
	if d.ExtraData == nil {
		d.ExtraData = map[string]string{}
	}
	for k, v := range other.ExtraData {
		// prefer existing value, only set if missing
		if _, ok := d.ExtraData[k]; !ok {
			d.ExtraData[k] = v
		}
	}
	if d.FirstSeen.IsZero() || (!other.FirstSeen.IsZero() && other.FirstSeen.Before(d.FirstSeen)) {
		d.FirstSeen = other.FirstSeen
	}
	if other.LastSeen.After(d.LastSeen) {
		d.LastSeen = other.LastSeen
	}
	if d.OpenPorts == nil {
		d.OpenPorts = map[string][]int{}
	}
	for protocol, ports := range other.OpenPorts {
		if _, ok := d.OpenPorts[protocol]; !ok {
			d.OpenPorts[protocol] = make([]int, len(ports))
			copy(d.OpenPorts[protocol], ports)
		} else {
			portSet := make(map[int]bool)
			for _, p := range d.OpenPorts[protocol] {
				portSet[p] = true
			}
			for _, p := range ports {
				if !portSet[p] {
					d.OpenPorts[protocol] = append(d.OpenPorts[protocol], p)
					portSet[p] = true
				}
			}
		}
	}
	if other.LastPortScan.After(d.LastPortScan) {
		d.LastPortScan = other.LastPortScan
	}
}
