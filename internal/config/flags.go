package config

const DefaultScanRate = 15

// Flags respresents command line flags for whosthere
type Flags struct {
	// RefreshRate is the rate (in seconds) at which whosthere will do a network scan.
	ScanRate *int
}

func NewFlags() *Flags {
	return &Flags{
		ScanRate: intPtr(DefaultScanRate),
	}
}

func intPtr(i int) *int {
	return &i
}
