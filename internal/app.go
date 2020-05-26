package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/urfave/cli/v2"

	"github.com/anuvu/zot/internal/client"
	"github.com/anuvu/zot/internal/server"
	"github.com/anuvu/zot/internal/standalone"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	tdb "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
)

type VersionInfo struct {
	Version         string       `json:",omitempty"`
	VulnerabilityDB *db.Metadata `json:",omitempty"`
}

var (
	templateFlag = cli.StringFlag{
		Name:    "template, t",
		Value:   "",
		Usage:   "output template",
		EnvVars: []string{"TRIVY_TEMPLATE"},
	}

	formatFlag = cli.StringFlag{
		Name:    "format, f",
		Value:   "table",
		Usage:   "format (table, json, template)",
		EnvVars: []string{"TRIVY_FORMAT"},
	}

	inputFlag = cli.StringFlag{
		Name:    "input, i",
		Value:   "",
		Usage:   "input file path instead of image name",
		EnvVars: []string{"TRIVY_INPUT"},
	}

	severityFlag = cli.StringFlag{
		Name:    "severity, s",
		Value:   strings.Join(types.SeverityNames, ","),
		Usage:   "severities of vulnerabilities to be displayed (comma separated)",
		EnvVars: []string{"TRIVY_SEVERITY"},
	}

	outputFlag = cli.StringFlag{
		Name:    "output, o",
		Usage:   "output file name",
		EnvVars: []string{"TRIVY_OUTPUT"},
	}

	exitCodeFlag = cli.IntFlag{
		Name:    "exit-code",
		Usage:   "Exit code when vulnerabilities were found",
		Value:   0,
		EnvVars: []string{"TRIVY_EXIT_CODE"},
	}

	skipUpdateFlag = cli.BoolFlag{
		Name:    "skip-update",
		Usage:   "skip db update",
		EnvVars: []string{"TRIVY_SKIP_UPDATE"},
	}

	downloadDBOnlyFlag = cli.BoolFlag{
		Name:    "download-db-only",
		Usage:   "download/update vulnerability database but don't run a scan",
		EnvVars: []string{"TRIVY_DOWNLOAD_DB_ONLY"},
	}

	resetFlag = cli.BoolFlag{
		Name:    "reset",
		Usage:   "remove all caches and database",
		EnvVars: []string{"TRIVY_RESET"},
	}

	clearCacheFlag = cli.BoolFlag{
		Name:    "clear-cache, c",
		Usage:   "clear image caches without scanning",
		EnvVars: []string{"TRIVY_CLEAR_CACHE"},
	}

	quietFlag = cli.BoolFlag{
		Name:    "quiet, q",
		Usage:   "suppress progress bar and log output",
		EnvVars: []string{"TRIVY_QUIET"},
	}

	noProgressFlag = cli.BoolFlag{
		Name:    "no-progress",
		Usage:   "suppress progress bar",
		EnvVars: []string{"TRIVY_NO_PROGRESS"},
	}

	ignoreUnfixedFlag = cli.BoolFlag{
		Name:    "ignore-unfixed",
		Usage:   "display only fixed vulnerabilities",
		EnvVars: []string{"TRIVY_IGNORE_UNFIXED"},
	}

	debugFlag = cli.BoolFlag{
		Name:    "debug, d",
		Usage:   "debug mode",
		EnvVars: []string{"TRIVY_DEBUG"},
	}

	removedPkgsFlag = cli.BoolFlag{
		Name:    "removed-pkgs",
		Usage:   "detect vulnerabilities of removed packages (only for Alpine)",
		EnvVars: []string{"TRIVY_REMOVED_PKGS"},
	}

	vulnTypeFlag = cli.StringFlag{
		Name:    "vuln-type",
		Value:   "os,library",
		Usage:   "comma-separated list of vulnerability types (os,library)",
		EnvVars: []string{"TRIVY_VULN_TYPE"},
	}

	cacheDirFlag = cli.StringFlag{
		Name:    "cache-dir",
		Value:   utils.DefaultCacheDir(),
		Usage:   "cache directory",
		EnvVars: []string{"TRIVY_CACHE_DIR"},
	}

	ignoreFileFlag = cli.StringFlag{
		Name:    "ignorefile",
		Value:   vulnerability.DefaultIgnoreFile,
		Usage:   "specify .trivyignore file",
		EnvVars: []string{"TRIVY_IGNOREFILE"},
	}

	timeoutFlag = cli.DurationFlag{
		Name:    "timeout",
		Value:   time.Second * 120,
		Usage:   "docker timeout",
		EnvVars: []string{"TRIVY_TIMEOUT"},
	}

	lightFlag = cli.BoolFlag{
		Name:    "light",
		Usage:   "light mode: it's faster, but vulnerability descriptions and references are not displayed",
		EnvVars: []string{"TRIVY_LIGHT"},
	}

	token = cli.StringFlag{
		Name:    "token",
		Usage:   "for authentication",
		EnvVars: []string{"TRIVY_TOKEN"},
	}

	tokenHeader = cli.StringFlag{
		Name:    "token-header",
		Value:   "Trivy-Token",
		Usage:   "specify a header name for token",
		EnvVars: []string{"TRIVY_TOKEN_HEADER"},
	}
)

func NewApp(version string) *cli.App {
	cli.AppHelpTemplate = `NAME:
  {{.Name}}{{if .Usage}} - {{.Usage}}{{end}}
USAGE:
  {{if .UsageText}}{{.UsageText}}{{else}}{{.HelpName}} {{if .VisibleFlags}}[options]{{end}} {{if .ArgsUsage}}{{.ArgsUsage}}{{else}}[arguments...]{{end}}{{end}}{{if .Version}}{{if not .HideVersion}}
VERSION:
  {{.Version}}{{end}}{{end}}{{if .Description}}
DESCRIPTION:
  {{.Description}}{{end}}{{if len .Authors}}
AUTHOR{{with $length := len .Authors}}{{if ne 1 $length}}S{{end}}{{end}}:
  {{range $index, $author := .Authors}}{{if $index}}
  {{end}}{{$author}}{{end}}{{end}}{{if .VisibleCommands}}
OPTIONS:
  {{range $index, $option := .VisibleFlags}}{{if $index}}
  {{end}}{{$option}}{{end}}{{end}}
`
	cli.VersionPrinter = func(c *cli.Context) {
		showVersion(c.String("cache-dir"), c.String("format"), c.App.Version, c.App.Writer)
	}

	app := cli.NewApp()
	app.Name = "trivy"
	app.Version = version
	app.ArgsUsage = "image_name"

	app.Usage = "A simple and comprehensive vulnerability scanner for containers"

	app.EnableBashCompletion = true

	app.Flags = []cli.Flag{
		&templateFlag,
		&formatFlag,
		&inputFlag,
		&severityFlag,
		&outputFlag,
		&exitCodeFlag,
		&skipUpdateFlag,
		&downloadDBOnlyFlag,
		&resetFlag,
		&clearCacheFlag,
		&quietFlag,
		&noProgressFlag,
		&ignoreUnfixedFlag,
		&debugFlag,
		&removedPkgsFlag,
		&vulnTypeFlag,
		&cacheDirFlag,
		&ignoreFileFlag,
		&timeoutFlag,
		&lightFlag,

		// deprecated options
		&cli.StringFlag{
			Name:    "only-update",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_ONLY_UPDATE"},
		},
		&cli.BoolFlag{
			Name:    "refresh",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_REFRESH"},
		},
		&cli.BoolFlag{
			Name:    "auto-refresh",
			Usage:   "deprecated",
			EnvVars: []string{"TRIVY_AUTO_REFRESH"},
		},
	}

	app.Commands = []*cli.Command{
		NewClientCommand(),
		NewServerCommand(),
	}

	app.Action = standalone.Run
	return app
}

func showVersion(cacheDir, outputFormat, version string, outputWriter io.Writer) {
	var dbMeta *db.Metadata

	metadata, _ := tdb.NewMetadata(afero.NewOsFs(), cacheDir).Get()
	if !metadata.UpdatedAt.IsZero() && !metadata.NextUpdate.IsZero() && metadata.Version != 0 {
		dbMeta = &db.Metadata{
			Version:    metadata.Version,
			Type:       metadata.Type,
			NextUpdate: metadata.NextUpdate.UTC(),
			UpdatedAt:  metadata.UpdatedAt.UTC(),
		}
	}

	switch outputFormat {
	case "json":
		b, _ := json.Marshal(VersionInfo{
			Version:         version,
			VulnerabilityDB: dbMeta,
		})
		fmt.Fprintln(outputWriter, string(b))
	default:
		output := fmt.Sprintf("Version: %s\n", version)
		if dbMeta != nil {
			var dbType string
			switch dbMeta.Type {
			case 0:
				dbType = "Full"
			case 1:
				dbType = "Light"
			}
			output += fmt.Sprintf(`Vulnerability DB:
  Type: %s
  Version: %d
  UpdatedAt: %s
  NextUpdate: %s
`, dbType, dbMeta.Version, dbMeta.UpdatedAt.UTC(), dbMeta.NextUpdate.UTC())
		}
		fmt.Fprintf(outputWriter, output)
	}
}

func NewClientCommand() *cli.Command {
	return &cli.Command{
		Name:    "client",
		Aliases: []string{"c"},
		Usage:   "client mode",
		Action:  client.Run,
		Flags: []cli.Flag{
			&templateFlag,
			&formatFlag,
			&inputFlag,
			&severityFlag,
			&outputFlag,
			&exitCodeFlag,
			&clearCacheFlag,
			&quietFlag,
			&ignoreUnfixedFlag,
			&debugFlag,
			&removedPkgsFlag,
			&vulnTypeFlag,
			&ignoreFileFlag,
			&cacheDirFlag,
			&timeoutFlag,

			// original flags
			&token,
			&tokenHeader,
			&cli.StringFlag{
				Name:    "remote",
				Value:   "http://localhost:4954",
				Usage:   "server address",
				EnvVars: []string{"TRIVY_REMOTE"},
			},
			&cli.StringSliceFlag{
				Name:    "custom-headers",
				Usage:   "custom headers",
				EnvVars: []string{"TRIVY_CUSTOM_HEADERS"},
			},
		},
	}
}

func NewServerCommand() *cli.Command {
	return &cli.Command{
		Name:    "server",
		Aliases: []string{"s"},
		Usage:   "server mode",
		Action:  server.Run,
		Flags: []cli.Flag{
			&skipUpdateFlag,
			&downloadDBOnlyFlag,
			&resetFlag,
			&quietFlag,
			&debugFlag,
			&cacheDirFlag,

			// original flags
			&token,
			&tokenHeader,
			&cli.StringFlag{
				Name:    "listen",
				Value:   "localhost:4954",
				Usage:   "listen address",
				EnvVars: []string{"TRIVY_LISTEN"},
			},
		},
	}
}
