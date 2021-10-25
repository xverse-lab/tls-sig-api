package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/xverse-lab/tls-sig-api/go/tls_sig_api"
)

func UnixTimeToString(t int64) string {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	return time.Unix(t, 0).In(loc).Format("2006-01-02 15:04:05")
}

func main() {
	var token string
	flag.StringVar(&token, "token", "", "token to parse")
	flag.Parse()

	if token == "" {
		log.Fatalln("please input token, you can input --help to get usage")
	}

	tokenInfo, err := tls_sig_api.ParseToken(token)
	if err != nil {
		log.Fatalf("parse token failed, %v", err)
	}
	fmt.Printf("ver\t: %v\nappid\t: %v\nuid\t: %v\nexpire\t: %v (%v)\nskVer\t: %v\n",
		tokenInfo.Ver, tokenInfo.Appid, tokenInfo.Uid, tokenInfo.Expire, UnixTimeToString(int64(tokenInfo.Expire)), tokenInfo.SkVer)
}
