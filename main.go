package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/bradenrayhorn/fake-oidc/oidc"
)

func main() {
	port := os.Getenv("FAKE_OIDC_HTTP_PORT")
	if len(port) == 0 {
		port = "7835"
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	server, err := oidc.NewServer(port)
	if err != nil {
		log.Fatalf("could not create fake-oidc server: %v", err)
		return
	}

	fmt.Printf("starting fake oidc server on %s\n", server.GetBoundAddr())

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
