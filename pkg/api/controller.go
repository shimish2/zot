package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/anuvu/zot/errors"
	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
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

func (c *Controller) setController() error {
	if err := c.validateConfig(); err != nil {
		return err
	}

	// print the current configuration, but strip secrets
	c.Log.Info().Interface("params", c.Config.Sanitize()).Msg("configuration settings")

	c.setImageStore()

	// Set basic routes
	c.setRouter()

	return nil
}

func (c *Controller) BaseRun() error {
	// Set basic configuration
	err := c.setController()
	if err != nil {
		c.Log.Error().Err(err).Msg("configuration validation failed")
	}

	// Create the listener
	l, err := c.createListener()
	if err != nil {
		return err
	}

	_ = NewRouteHandler(c)

	// Setup Server
	return c.setupServer(l)
}

func (c *Controller) createListener() (net.Listener, error) {
	addr := c.getAddress()
	return net.Listen("tcp", addr)
}

func (c *Controller) getAddress() string {
	return fmt.Sprintf("%s:%s", c.Config.HTTP.Address, c.Config.HTTP.Port)
}

func (c *Controller) setupServer(l net.Listener) error {
	if c.Config.HTTP.TLS != nil && c.Config.HTTP.TLS.Key != "" && c.Config.HTTP.TLS.Cert != "" {
		if c.Config.HTTP.TLS.CACert != "" {
			c.setTlsConfig()
		}

		return c.startTLSServer(l)
	}

	return c.startServer(l)
}

func (c *Controller) validateConfig() error {
	return c.Config.Validate(c.Log)
}

func (c *Controller) setImageStore() {
	c.ImageStore = storage.NewImageStore(c.Config.Storage.RootDirectory, c.Config.Storage.GC,
		c.Config.Storage.Dedupe, c.Log)
	if c.ImageStore == nil {
		// we can't proceed without at least a image store
		os.Exit(1)
	}
}

func (c *Controller) setRouter() {
	engine := mux.NewRouter()
	engine.Use(log.SessionLogger(c.Log), handlers.RecoveryHandler(handlers.RecoveryLogger(c.Log),
		handlers.PrintRecoveryStack(false)))

	c.Router = engine
	c.Router.UseEncodedPath()
}

func (c *Controller) setServer(addr string) {
	server := &http.Server{Addr: addr, Handler: c.Router}
	c.Server = server
}

func (c *Controller) setTlsConfig() {
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

	c.Server.TLSConfig = &tls.Config{
		ClientAuth:               clientAuth,
		ClientCAs:                caCertPool,
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
	}
	c.Server.TLSConfig.BuildNameToCertificate() // nolint: staticcheck
}

func (c *Controller) startServer(l net.Listener) error {
	return c.Server.Serve(l)
}

func (c *Controller) startTLSServer(l net.Listener) error {
	return c.Server.ServeTLS(l, c.Config.HTTP.TLS.Cert, c.Config.HTTP.TLS.Key)
}
