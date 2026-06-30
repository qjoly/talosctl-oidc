// Command mock-talos-api runs a fake Talos API server for the integration test.
// It serves the GenerateClientConfiguration RPC over mTLS and writes a
// talosconfig the talosctl-oidc server uses to authenticate. Tests only.
package main

import (
	"flag"
	"log"
	"net"

	"github.com/qjoly/talosctl-oidc/internal/mocktalos"
)

func main() {
	talosconfigPath := flag.String("talosconfig", "talosconfig", "path to write the generated talosconfig")
	listen := flag.String("listen", ":50000", "address to listen on (apid default port is 50000)")
	flag.Parse()

	s, err := mocktalos.New()
	if err != nil {
		log.Fatalf("creating mock: %v", err)
	}

	if err := s.WriteTalosconfig(*talosconfigPath, "127.0.0.1"); err != nil {
		log.Fatalf("writing talosconfig: %v", err)
	}

	lis, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}

	log.Printf("mock Talos API listening on %s, talosconfig written to %s", *listen, *talosconfigPath)
	if err := s.GRPCServer().Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
