package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/miekg/dns"
	"github.com/natesales/doq/pkg/client"
	log "github.com/sirupsen/logrus"
)

var (
	server             = flag.String("server", "[::1]:784", "DoQ server")
	insecureSkipVerify = flag.Bool("insecureSkipVerify", false, "skip TLS certificate validation")
	dnssec             = flag.Bool("dnssec", true, "send DNSSEC flag")
	rec                = flag.Bool("recursion", true, "send RD flag")
	queryName          = flag.String("queryName", "", "DNS QNAME")
	queryType          = flag.String("queryType", "", "DNS QTYPE")
)

func main() {
	flag.Parse()

	// Validate flags
	if *queryName == "" || *queryType == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Parse QNAME/QTYPE
	qname := dns.Fqdn(*queryName)
	qtype, success := dns.StringToType[*queryType]
	if !success {
		log.Fatalf("invalid DNS QTYPE \"%s\"\n", *queryType)
	}

	// Connect to DoQ server
	doqClient, err := client.New(*server, *insecureSkipVerify)
	if err != nil {
		log.Fatalf("client create: %s\n", err)
	}
	defer doqClient.Close() // Cleanup the QUIC session once we're done with it

	// Create the DNS query message
	msg := dns.Msg{}
	msg.SetQuestion(qname, qtype)
	msg.SetEdns0(4096, *dnssec)
	msg.RecursionDesired = *rec

	// Send query
	rxMsg, err := doqClient.SendQuery(msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(rxMsg.String())
}