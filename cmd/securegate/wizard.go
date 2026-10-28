package main

import (
	"context"

	"github.com/jgermade/securegate/internal/wizard"
)

func runWizard(path string, accessible bool) error {
	w := &wizard.Wizard{Path: path, Accessible: accessible}
	return w.Run(context.Background())
}
