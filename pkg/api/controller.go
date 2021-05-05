package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/anuvu/zot/errors"
	ext "github.com/anuvu/zot/pkg/extensions"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

const (
	idleTimeout = 120 * time.Second
)

type Controller struct {
	Config     *Config
	Router     *mux.Router
	ImageStore *storage.ImageStore
	Log        log.Logger
	Server     *http.Server
}

func NewController(config *Config) *Controller {
	return &Controller{Config: config, Log: log.NewLogger(config.Log.Level, config.Log.Output)}
}

func DefaultHeaders() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// CORS
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")

			// handle the request
			next.ServeHTTP(w, r)
		})
	}
}

func (c *Controller) Run() error {
	// validate configuration
	if err := c.Config.Validate(c.Log); err != nil {
		c.Log.Error().Err(err).Msg("configuration validation failed")
		return err
	}

	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	engine := mux.NewRouter()
	engine.Use(DefaultHeaders(),
		log.SessionLogger(c.Log),
		handlers.RecoveryHandler(handlers.RecoveryLogger(c.Log),
			handlers.PrintRecoveryStack(false)))

	c.ImageStore = storage.NewImageStore(c.Config.Storage.RootDirectory, c.Config.Storage.GC,
		c.Config.Storage.Dedupe, c.Log)
	if c.ImageStore == nil {
		// we can't proceed without at least a image store
		os.Exit(1)
	}

	// Enable extensions if extension config is provided
	if c.Config != nil && c.Config.Extensions != nil {
		ext.EnableExtensions(c.Config.Extensions, c.Log, c.Config.Storage.RootDirectory)
	}

	c.Router = engine
	c.Router.UseEncodedPath()
	_ = NewRouteHandler(c)

	addr := fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
	server := &http.Server{
		Addr:        addr,
		Handler:     c.Router,
		IdleTimeout: idleTimeout,
	}
	c.Server = server

	// Create the listener
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if c.Config.HTTP.TLS != nil && c.Config.HTTP.TLS.Key != "" && c.Config.HTTP.TLS.Cert != "" {
		if c.Config.HTTP.TLS.CACert != "" {
			clientAuth := tls.VerifyClientCertIfGiven
			if (c.Config.HTTP.Auth == nil || c.Config.HTTP.Auth.HTPasswd.Path == "") && !c.Config.HTTP.AllowReadAccess {
				clientAuth = tls.RequireAndVerifyClientCert
			}

			caCert, err := ioutil.ReadFile(c.Config.HTTP.TLS.CACert)
			if err != nil {
				panic(err)
			}

			caCertPool := x509.NewCertPool()

			if !caCertPool.AppendCertsFromPEM(caCert) {
				panic(errors.ErrBadCACert)
			}

			server.TLSConfig = &tls.Config{
				ClientAuth:               clientAuth,
				ClientCAs:                caCertPool,
				PreferServerCipherSuites: true,
				MinVersion:               tls.VersionTLS12,
			}
			server.TLSConfig.BuildNameToCertificate() // nolint: staticcheck
		}

		return server.ServeTLS(l, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
	}

	return server.Serve(l)
}
