// +build extension

package api

import (
	gqlHandler "github.com/99designs/gqlgen/graphql/handler"
	"github.com/anuvu/zot/pkg/extensions/search"
)

func (rh *RouteHandler) NewExtensionRoutes() {
	// Zot Search Extension Router
	if rh.c.Config != nil && rh.c.Config.Extensions != nil {
		rh.c.Router.PathPrefix("/query").Methods("GET", "POST").Handler(rh.searchHandler())
	}
}

func (rh *RouteHandler) searchHandler() *gqlHandler.Server {
	resConfig := search.GetResolverConfig(rh.c.Config.Storage.RootDirectory, rh.c.Log, rh.c.ImageStore)
	return gqlHandler.NewDefaultServer(search.NewExecutableSchema(resConfig))
}
