package tls_sig_api

import (
	"github.com/xverse-lab/tls-sig-api/go/tls_sig_api"
	"testing"
	"time"
)

var expire uint32 = 2
var token string
var sk = "02fa4432134a4427b59849c623d6f0ab"

func TestGenToken(t *testing.T) {
	appid := "f4c1a9665082406a9adb46db953c0453"
	uid := "10000000"
	skVer := "202108041200"
	var err error
	token, err = tls_sig_api.GenToken(appid, uid, sk, skVer, expire)
	if err != nil {
		t.Fatalf("gen token failed, %v", err)
	}

	t.Log(token)
}

func TestVerifyToken(t *testing.T) {
	err := tls_sig_api.VerifyToken(token, sk)
	if err != nil {
		t.Fatalf("verify token failed, %v", err)
	}

	time.Sleep(time.Duration(expire+1) * time.Second)
	err = tls_sig_api.VerifyToken(token, sk)
	if err == nil {
		t.Fatalf("expect err, but err is nil")
	}
	t.Log(err)
}
