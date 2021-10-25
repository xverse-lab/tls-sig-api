package tls_sig_api

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"
)

/* GenToken 生成鉴权token
 * 入参说明：
 * appid - 应用ID
 * uid - 用户ID
 * sk - 计算token用的加密秘钥
 * skVer - 密钥版本
 * expire - token有效期, 单位是秒，假如token有效期为一天，则expire填入 24*3600，token在一天后将失效
 * 出参说明：
 * 第一个string为正常返回的token
 * 第二个error在生成token失败时返回错误信息
 */
func GenToken(appid, uid, sk, skVer string, expire uint32) (string, error) {
	return genToken(appid, uid, sk, skVer, expire)
}

/* VerifyToken 校验token是否有效
 * 入参说明：
 * token - 生成的鉴权票据
 * sk - 计算token用的加密秘钥
 * 出参说明：
 * error为nil表示token合法有效，否则表示无效，返回错误信息
 */
func VerifyToken(token, sk string) error {
	return verifyToken(token, sk)
}

const (
	VERSION string = "1.0.0"
)

type TokenInfo struct {
	Ver    string `json:"ver"`    // 版本号
	Appid  string `json:"appid"`  // 应用ID
	Uid    string `json:"uid"`    // 用户ID
	Salt   uint32 `json:"salt"`   // salt，保证每次生成的token不同
	Expire uint32 `json:"expire"` // token过期时间
	Sig    string `json:"sig"`    // 签名
	SkVer  string `json:"skver"`  // 密钥版本
}

func genToken(appid, uid, sk, skVer string, expire uint32) (string, error) {
	if appid == "" || uid == "" || sk == "" || skVer == "" || expire == 0 {
		return "", fmt.Errorf("invalid argument")
	}

	tokenInfo := &TokenInfo{
		Ver:    VERSION,
		Appid:  appid,
		Uid:    uid,
		Salt:   rand.Uint32(),
		Expire: uint32(time.Now().Unix() + int64(expire)),
		SkVer:  skVer,
	}
	tokenInfo.Sig = genSig(tokenInfo, sk)

	data, err := json.Marshal(tokenInfo)
	if err != nil {
		return "", err
	}

	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err = w.Write(data); err != nil {
		return "", fmt.Errorf("zlib write data failed, %v", err)
	}
	if err = w.Close(); err != nil {
		return "", fmt.Errorf("zlib writer close failed, %v", err)
	}

	return base64urlEncode(b.Bytes()), nil
}

func ParseToken(token string) (*TokenInfo, error) {
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}

	data, err := base64urlDecode(token)
	if err != nil {
		return nil, fmt.Errorf("base64urlDecode failed, %v", err)
	}

	var b bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zlib NewReader failed, %v", err)
	}
	_, err = io.Copy(&b, r)
	if err != nil {
		return nil, fmt.Errorf("io copy failed, %v", err)
	}

	var tokenInfo TokenInfo
	if err = json.Unmarshal(b.Bytes(), &tokenInfo); err != nil {
		return nil, fmt.Errorf("json unmarshal failed, %v", err)
	}

	return &tokenInfo, nil
}

func verifyToken(token, sk string) error {
	if token == "" || sk == "" {
		return fmt.Errorf("invalid argument")
	}

	data, err := base64urlDecode(token)
	if err != nil {
		return fmt.Errorf("base64urlDecode failed, %v", err)
	}

	var b bytes.Buffer
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("zlib NewReader failed, %v", err)
	}
	_, err = io.Copy(&b, r)
	if err != nil {
		return fmt.Errorf("io copy failed, %v", err)
	}

	var tokenInfo TokenInfo
	if err = json.Unmarshal(b.Bytes(), &tokenInfo); err != nil {
		return fmt.Errorf("json unmarshal failed, %v", err)
	}

	if tokenInfo.Ver == "" || tokenInfo.Appid == "" || tokenInfo.Uid == "" || tokenInfo.Sig == "" || tokenInfo.SkVer == "" || tokenInfo.Salt == 0 || tokenInfo.Expire == 0 {
		return fmt.Errorf("invalid token")
	}

	if tokenInfo.Expire < uint32(time.Now().Unix()) {
		return fmt.Errorf("expired token")
	}

	if tokenInfo.Sig != genSig(&tokenInfo, sk) {
		return fmt.Errorf("token signature not match")
	}

	return nil
}

func genSig(tokenInfo *TokenInfo, sk string) string {
	msg := fmt.Sprintf("%v%v%v%v%v", tokenInfo.Appid, tokenInfo.Uid, tokenInfo.Salt, tokenInfo.Expire, tokenInfo.SkVer)
	return hmacsha256(msg, sk)
}

func hmacsha256(msg, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func base64urlEncode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	str = strings.Replace(str, "+", "*", -1)
	str = strings.Replace(str, "/", "-", -1)
	str = strings.Replace(str, "=", "_", -1)
	return str
}

func base64urlDecode(str string) ([]byte, error) {
	str = strings.Replace(str, "_", "=", -1)
	str = strings.Replace(str, "-", "/", -1)
	str = strings.Replace(str, "*", "+", -1)
	return base64.StdEncoding.DecodeString(str)
}
