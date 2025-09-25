package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/bradenrayhorn/fake-oidc/oidc"
)

func main() {
	// Parse command line flags
	var (
		configFile = flag.String("config", "", "Path to configuration file (JSON)")
		port       = flag.String("port", "", "Port to listen on (overrides config and env)")
		host       = flag.String("host", "", "Host to bind to (overrides config and env)")
		verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	// Get configuration from environment variables if not provided via flags
	if *port == "" {
		*port = os.Getenv("FAKE_OIDC_HTTP_PORT")
		if *port == "" {
			*port = "7835"
		}
	}

	if *host == "" {
		*host = os.Getenv("FAKE_OIDC_HTTP_HOST")
	}

	// Load configuration
	config, err := oidc.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("could not load configuration: %v", err)
	}

	// Override config with command line parameters
	if *host != "" {
		config.Server.Host = *host
	}
	if *port != "" {
		config.Server.Port = *port
	}
	config.Features.EnableLogging = *verbose

	fmt.Printf("Configuration loaded from: %s\n", *configFile)
	if *configFile == "" {
		fmt.Println("Using default configuration")
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	server, err := oidc.NewServerWithConfig(config)
	if err != nil {
		log.Fatalf("could not create fake-oidc server: %v", err)
		return
	}

	fmt.Printf("starting fake oidc server on %s\n", server.GetBoundAddr())
	fmt.Printf("issuer URL: %s\n", config.GetIssuerURL())
	fmt.Printf("client ID: %s\n", config.Client.ID)

	go func() {
		err = server.Open()
		if err != nil {
			log.Fatalf("could not start fake-oidc server: %v", err)
			return
		}
	}()

	<-c
	_ = server.Close()
}
