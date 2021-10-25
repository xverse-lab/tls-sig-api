# 使用示例

```go
package main

import (
	"log"
	
	"github.com/xverse-lab/tls-sig-api/go/tls_sig_api"
)

func main() {
	appid := "test_appid"
	uid := "test_uid"
	skVer := "test_sk_ver"
	sk := "test_sk"
	expire := 30
	token, err := tls_sig_api.GenToken(appid, uid, sk, skVer, uint32(expire))
	if err != nil {
		log.Fatalf("gen token failed, %v", err)
	}
	log.Println(token)
}
```