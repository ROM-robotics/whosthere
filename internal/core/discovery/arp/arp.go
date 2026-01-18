package arp

import (
	"context"

	"github.com/ramonvermeulen/whosthere/internal/core/discovery"
	"go.uber.org/zap"
)

var _ discovery.Scanner = (*Scanner)(nil)

// Scanner implements ARP-based discovery by reading the ARP cache.
// Optional Sweeper can populate the cache in the background.
type Scanner struct {
	Sweeper Sweeper

	logger *zap.Logger
}

func NewScanner(sweeper Sweeper) *Scanner {
	return &Scanner{Sweeper: sweeper}
}

func (s *Scanner) Name() string { return "arp" }

// Scan performs ARP discovery.
func (s *Scanner) Scan(ctx context.Context, out chan<- discovery.Device) error {
	if s.logger == nil {
		s.logger = zap.L().With(zap.String("scanner", s.Name()))
	}

	if s.Sweeper != nil {
		s.Sweeper.Start(ctx)
	}

	return s.readARPCache(ctx, out)
}
