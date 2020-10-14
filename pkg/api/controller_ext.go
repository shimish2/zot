// +build extension

package api

import (
	"time"

	cveinfo "github.com/anuvu/zot/pkg/extensions/search/cve"
)

func (c *Controller) ExtRun() error {
	err := c.setController()
	if err != nil {
		c.Log.Error().Err(err).Msg("configuration validation failed")
		return err
	}

	rh := NewRouteHandler(c)

	rh.NewExtensionRoutes()

	l, err := c.createListener()
	if err != nil {
		return err
	}

	// Setup Server
	return c.setupServer(l)
}

func (c *Controller) EnableExtension() {
	// Updating the CVE Database
	if c.Config != nil && c.Config.Extensions != nil && c.Config.Extensions.Search != nil &&
		c.Config.Extensions.Search.CVE != nil {
		defaultUpdateInterval, _ := time.ParseDuration("2h")

		if c.Config.Extensions.Search.CVE.UpdateInterval < defaultUpdateInterval {
			c.Config.Extensions.Search.CVE.UpdateInterval = defaultUpdateInterval
			c.Log.Warn().Msg("CVE update interval set to too-short interval <= 1, changing update duration to 2 hours and continuing.") // nolint: lll
		}

		go func() {
			for {
				c.Log.Info().Msg("Updating the CVE database")

				err := cveinfo.UpdateCVEDb(c.Config.Storage.RootDirectory, c.Log)
				if err != nil {
					panic(err)
				}

				c.Log.Info().Str("Db update completed, next update scheduled after", c.Config.Extensions.Search.CVE.UpdateInterval.String()).Msg("") //nolint: lll

				time.Sleep(c.Config.Extensions.Search.CVE.UpdateInterval)
			}
		}()
	} else {
		c.Log.Info().Msg("Cve config not provided, skipping cve update")
	}
}
