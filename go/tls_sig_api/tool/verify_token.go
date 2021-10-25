package main

import (
	"flag"
	"log"

	"github.com/xverse-lab/tls-sig-api/go/tls_sig_api"
)

func main() {
	var token, sk string
	flag.StringVar(&token, "token", "", "token to verify")
	flag.StringVar(&sk, "sk", "", "secret key")
	flag.Parse()

	if token == "" || sk == "" {
		log.Fatalln("please input token and sk, you can input --help to get usage")
	}

	err := tls_sig_api.VerifyToken(token, sk)
	if err != nil {
		log.Fatalf("invalid token, %v", err)
	}
	log.Println("verify success")
}
