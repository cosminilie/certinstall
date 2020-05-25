package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	cinst "github.com/cosminilie/certinstall"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func main() {

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "debug, d", Aliases: []string{"v"}, Usage: "Run in debug mode"},
			&cli.BoolFlag{Name: "silent, q", Aliases: []string{"q"}, Usage: "Run in silent mode"},
			&cli.BoolFlag{Name: "downloadonly, d", Aliases: []string{"d"}, Usage: "Download only"},
		},
		Commands: []*cli.Command{
			{
				Name:    "url",
				Aliases: []string{"u"},
				Usage:   "add a ca from an url",
				Action: func(c *cli.Context) error {
					config := zap.NewProductionConfig()
					if c.Bool("debug") {
						config.Level.SetLevel(zap.DebugLevel)
					}
					if c.Bool("silent") {
						config.Level.SetLevel(zap.PanicLevel)
					}
					logger, err := config.Build()
					defer logger.Sync()

					logger.Sugar().Infow("plucking certs",
						"url", c.Args().First(),
					)
					cacert, err := cinst.WebPlucker(logger, c.Args().First())
					if err != nil {
						return err
					}

					logger.Sugar().Infow("found ca cert",
						"commonName", cacert.Subject.CommonName,
						"url", c.Args().First(),
					)

					if c.Bool("downloadonly") {
						cacertfile, err := ioutil.TempFile("", "cacert.*.crt")
						if err != nil {
							log.Fatal(err)
							cli.Exit(fmt.Sprintf("failed creating cert file %s", cacertfile.Name()), 1)
						}

						if _, err := cacertfile.Write(cacert.Raw); err != nil {
							cacertfile.Close()
							logger.Sugar().Fatalw("encountered error while writing ca cert to file", "file", cacertfile.Name(), err)
							cli.Exit(fmt.Sprintf("failed writing cert file %s", cacertfile.Name()), 1)
						}
						logger.Sugar().Infow("wrote cert to file",
							"file", cacertfile.Name(),
						)

						if err := cacertfile.Close(); err != nil {
							logger.Sugar().Fatalw("encountered error while closing file", "file", cacertfile.Name(), err)
							cli.Exit(fmt.Sprintf("failed closing file %s", cacertfile.Name()), 1)
						}

						ec := cli.Exit(fmt.Sprintf("wrote file %s", cacertfile.Name()), 0)
						return ec
					}

					if cinst.IsJavaInstalled(logger) {
						logger.Sugar().Infow("found java on the machine, attempting to install cert in cacerts")
						err = cinst.JavaCertImporter(logger, cacert, cacert.SerialNumber)
						if err != nil {
							return err
						}
						logger.Sugar().Infow("java cert installation completed successfully")
					} else {
						logger.Sugar().Infow("java not installed, skipping ....")
					}

					if cinst.IsFirefoxInstalled(logger) {
						logger.Sugar().Infow("found firefox on the machine, attempting to install cert in certdb")
						err = cinst.FirefoxCertImporter(logger, cacert, cacert.SerialNumber)
						if err != nil {
							return err
						}
						logger.Sugar().Infow("firefox cert installation completed successfully")
					} else {
						logger.Sugar().Infow("nss certutil not installed, skipping firefox cert installation ....")
					}

					err = cinst.WindowStoreCertImporter(logger, cacert, cacert.SerialNumber)
					logger.Sugar().Infow("importing into windows cert store")
					if err != nil {
						return err
					}
					logger.Sugar().Infow("system cert installation completed successfully")
					return nil
				},
			},
			{
				Name:    "k8s",
				Aliases: []string{"k"},
				Usage:   "add the ca from a kubernetes cluster",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name: "secret",
						Action: func(c *cli.Context) error {
							fmt.Println("provide secret to search for CA: ", c.Args().First())
							return nil
						},
					},
				},
				Action: func(c *cli.Context) error {
					fmt.Println("found CA cert in k8s cluster: ", c.Args().First())
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
