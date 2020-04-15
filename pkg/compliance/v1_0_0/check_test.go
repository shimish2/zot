//nolint (dupl)
package v1_0_0_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/anuvu/zot/pkg/api"
	"github.com/anuvu/zot/pkg/compliance"
	"github.com/anuvu/zot/pkg/compliance/v1_0_0"
	"github.com/phayes/freeport"
	"gopkg.in/resty.v1"
)

const (
	DBTestPath = "../../../data/DB/ZotSearch.DB"
)

var (
	listenAddress = "127.0.0.1"
)

func TestWorkflows(t *testing.T) {
	ctrl, randomPort := startServer()
	defer stopServer(ctrl)
	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address: listenAddress,
		Port:    randomPort,
	})
}

func TestWorkflowsOutputJSON(t *testing.T) {
	ctrl, randomPort := startServer()
	defer stopServer(ctrl)
	v1_0_0.CheckWorkflows(t, &compliance.Config{
		Address:    listenAddress,
		Port:       randomPort,
		OutputJSON: true,
	})
}

// start local server on random open port
func startServer() (*api.Controller, string) {
	portInt, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	randomPort := fmt.Sprintf("%d", portInt)
	fmt.Println(randomPort)

	config := api.NewConfig()
	config.HTTP.Address = listenAddress
	config.HTTP.Port = randomPort
	ctrl := api.NewController(config)
	dir, err := ioutil.TempDir("", "oci-repo-test")
	if err != nil {
		panic(err)
	}

	ctrl.Config.Storage.RootDirectory = dir
	ctrl.DBPath = DBTestPath
	go func() {
		// this blocks
		if err := ctrl.Run(); err != nil {
			return
		}
	}()

	baseURL := fmt.Sprintf("http://%s:%s", listenAddress, randomPort)
	for {
		// poll until ready
		resp, _ := resty.R().Get(baseURL)
		if resp.StatusCode() == 404 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	return ctrl, randomPort
}

func stopServer(ctrl *api.Controller) {
	ctrl.Server.Shutdown(context.Background())
	ctrl.DB.Close()
	os.RemoveAll(ctrl.Config.Storage.RootDirectory)
}
