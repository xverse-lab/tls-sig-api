package main

import (
	"flag"
	"log"

	"github.com/xverse-lab/tls-sig-api/go/tls_sig_api"
)

func main() {
	var appid, uid, sk, skVer string
	var expire uint
	flag.StringVar(&appid, "appid", "", "")
	flag.StringVar(&uid, "uid", "", "")
	flag.StringVar(&sk, "sk", "", "secret key")
	flag.StringVar(&skVer, "skVer", "", "secret key version")
	flag.UintVar(&expire, "expire", 0, "token expire time")
	flag.Parse()

	if appid == "" || uid == "" || sk == "" || skVer == "" || expire == 0 {
		log.Fatalln("please input appid, uid, sk, skver, expire, you can input --help to get usage")
	}

	token, err := tls_sig_api.GenToken(appid, uid, sk, skVer, uint32(expire))
	if err != nil {
		log.Fatalf("gen token failed, %v", err)
	}
	log.Println(token)
}
