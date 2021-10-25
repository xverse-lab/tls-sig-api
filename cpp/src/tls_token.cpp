#include "tls_token.h"
#include <iostream>
#include <sstream>
#include <random>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <zlib.h>
#include "rapidjson/writer.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/prettywriter.h"

namespace inner {
const string VERSION = "1.0.0";

static string HmacSha256(const string &key, const string &msg);
static int Base64Encode(const void* data, size_t data_len, string &base64_buf);
static int Base64Decode(const char* data, size_t data_len, string &raw);
static int JsonToToken(const rapidjson::Document &json, string &token, string &errmsg);
static int TokenToJson(const string &token, string &json, string &errmsg);
static int TokenToJson(const string &token, rapidjson::Document &doc, string &errmsg);
static int Base64EncodeUrl(const void *data, size_t data_len, string &base64);
static int Base64DecodeUrl(const char *data, size_t data_len, string &raw);
static int Compress(const void *data, size_t data_len, string &compressed);
static int Uncompress(const void *data, size_t data_len, string &uncompressed);
static string GetStringFromJsonDoc(rapidjson::Document &doc, const string &key);

static uint32_t GenSalt() {
    std::random_device r;
    return r();
}

static string GenSignatrue(const string &appid, const string &uid, uint32_t salt, uint64_t expire_time, const string& sk_ver, const string &key) {
    std::stringstream ss;
    ss << appid << uid << salt << expire_time << sk_ver;   
    return HmacSha256(key, ss.str());
}

static string HmacSha256(const string &key, const string &msg) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    HMAC(EVP_sha256(), (const unsigned char*)key.data(), key.length(), (const unsigned char*)msg.data(), msg.length(), &md[0], &md_len);
    string base64_result;
    Base64Encode(md, md_len, base64_result);
    return base64_result;
}

static string Base64Strip(const void* data, size_t data_len) {
    const char* d = static_cast<const char*>(data);
    string s;
    s.reserve(data_len);
    for (size_t i = 0; i < data_len; ++i) {
        if (isspace(d[i]))
            continue;
        s.append(1, d[i]);
    }
    return s;
}

static int Base64Encode(const void* data, size_t data_len, string &base64_buf) {
    div_t res = std::div(data_len, 3);
    size_t outlen = res.quot * 4 + (res.rem ? 4 : 0);
    base64_buf.resize(outlen);
    EVP_EncodeBlock(reinterpret_cast<uint8_t*>(const_cast<char*>(base64_buf.data())), reinterpret_cast<const uint8_t*>(data), data_len);
    return 0;
}

static int Base64Decode(const char* data, size_t data_len, string &raw) {
    raw.resize(data_len);
    string base64 = Base64Strip(data, data_len);
    int outlen = EVP_DecodeBlock(reinterpret_cast<uint8_t*>(const_cast<char*>(raw.data())), reinterpret_cast<const uint8_t*>(base64.data()), base64.size());
    if(outlen < 0) return outlen;
    if (base64.size() > 1 && base64[base64.size() - 1] == '=') {
        --outlen;
        if (base64.size() > 2 && base64[base64.size() - 2] == '=') --outlen;
    }
    raw.resize(outlen);
    return 0;
}

static int JsonToToken(const rapidjson::Document &json, string &token, string &errmsg) {
    rapidjson::StringBuffer s;
    rapidjson::Writer<rapidjson::StringBuffer> w(s);
    json.Accept(w);

    string compressed;
    int ret = Compress(s.GetString(), s.GetSize(), compressed);
    if (ret != Z_OK) {
        errmsg = string("compress failed ") + std::to_string(ret);
        return E_COMPRESS_ERR;
    }
    ret = Base64EncodeUrl(compressed.data(), compressed.size(), token);
    if (ret != 0) {
        errmsg = string("Base64EncodeUrl failed ") + std::to_string(ret);
        return E_ENCODE_ERR;
    }
    return E_OK;
}

static int TokenToJson(const string &token, string &json, string &errmsg) {
    string compressed;
    int ret = Base64DecodeUrl(token.data(), token.size(), compressed);
    if (ret != 0) {
        errmsg = string("Base64DecodeUrl failed ") + std::to_string(ret);
        return E_DECODE_ERR;
    }
    ret = Uncompress(compressed.data(), compressed.size(), json);
    if (ret != Z_OK) {
        errmsg = string("uncompress failed ") + std::to_string(ret);
        return E_UNCOMPRESS_ERR;
    }
    return E_OK;
}

static int TokenToJson(const string &token, rapidjson::Document &doc, string &errmsg) {
    string json;
    int ret = TokenToJson(token, json, errmsg);
    if (ret != E_OK) return ret;
    if (doc.Parse(json.data()).HasParseError()) {
        errmsg = "parse json failed";
        return E_PARSE_ERR;
    }
    return E_OK;
}

static int Base64EncodeUrl(const void *data, size_t data_len, string &base64)
{
    int ret = Base64Encode(data, data_len, base64);
    if (ret != 0) return ret;
    for (size_t i = 0; i < base64.size(); ++i) {
        switch (base64[i]) {
        case '+':
            base64[i] = '*';
            break;
        case '/':
            base64[i] = '-';
            break;
        case '=':
            base64[i] = '_';
            break;
        default:
            break;
        }
    }
    return 0;
}

static int Base64DecodeUrl(const char *data, size_t data_len, string &raw) {
    string base64(data, data_len);
    for (size_t i = 0; i < base64.size(); ++i) {
        switch (base64[i]) {
        case '*':
            base64[i] = '+';
            break;
        case '-':
            base64[i] = '/';
            break;
        case '_':
            base64[i] = '=';
            break;
        default:
            break;
        }
    }
    return Base64Decode(base64.data(), base64.size(), raw);
}

static int Compress(const void *data, size_t data_len, string &compressed) {
    compressed.resize(std::max(data_len, static_cast<size_t>(128)));
    uLongf uLen = compressed.size();
    int ret = compress2(reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen, reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) {
        compressed.resize(uLen);
        return ret;
    }
    if (ret != Z_MEM_ERROR) return ret;
    compressed.resize(compressed.size() * 2);
    uLen = compressed.size();
    ret = compress2(reinterpret_cast<Bytef*>(const_cast<char*>(compressed.data())), &uLen, reinterpret_cast<const Bytef*>(data), data_len, Z_BEST_SPEED);
    if(ret == Z_OK) compressed.resize(uLen);
    return ret;
}

static int Uncompress(const void *data, size_t data_len, string &uncompressed) {
    int ret = 0;
    uncompressed.resize(data_len * 2);
    do {
        uncompressed.resize(uncompressed.size() * 2);
        uLongf uLen = uncompressed.size();
        ret = uncompress(reinterpret_cast<Bytef*>(const_cast<char*>(uncompressed.data())), &uLen, reinterpret_cast<const Bytef*>(data), data_len);
        if (ret == Z_OK) uncompressed.resize(uLen);
    } while (ret == Z_MEM_ERROR);
    return ret;
}

static string GetStringFromJsonDoc(rapidjson::Document &doc, const string &key) {
    if (doc.HasMember(key.c_str()) && doc[key.c_str()].IsString()) {
        return doc[key.c_str()].GetString();
    }
    return "";
}

static uint32_t GetUint32FromJsonDoc(rapidjson::Document &doc, const string &key) {
    if (doc.HasMember(key.c_str()) && doc[key.c_str()].IsUint()) {
        return doc[key.c_str()].GetUint();
    }
    return 0;
}
}

using namespace inner;

int GenToken(uint32_t expire, const string &appid, const string &uid, const string &sk, const string &sk_ver, string &token, string &err_msg) {
    if (expire == 0) return E_EXPIRE_INVALID;
    if (appid.empty()) return E_APPID_EMPTY;
    if (uid.empty()) return E_UID_EMPTY;
    if (sk.empty()) return E_SK_EMPTY;
    if (sk_ver.empty()) return E_SK_VER_EMPTY;

    uint64_t expire_time = time(NULL) + expire;
    uint32_t salt = GenSalt();
    string sig = GenSignatrue(appid, uid, salt, expire_time, sk_ver, sk);
    rapidjson::Document doc;
    doc.SetObject();
    doc.AddMember("ver", rapidjson::Value(VERSION.c_str(), VERSION.length(), doc.GetAllocator()), doc.GetAllocator());
    doc.AddMember("appid", rapidjson::Value(appid.c_str(), appid.length(), doc.GetAllocator()), doc.GetAllocator());
    doc.AddMember("uid", rapidjson::Value(uid.c_str(), uid.length(), doc.GetAllocator()), doc.GetAllocator());
    doc.AddMember("skver", rapidjson::Value(sk_ver.c_str(), sk_ver.length(), doc.GetAllocator()), doc.GetAllocator());
    doc.AddMember("salt", salt, doc.GetAllocator());
    doc.AddMember("expire", expire_time, doc.GetAllocator());
    doc.AddMember("sig", rapidjson::Value(sig.c_str(), sig.length(), doc.GetAllocator()), doc.GetAllocator());
    return JsonToToken(doc, token, err_msg);
}

int VerifyToken(const string& token, const string &sk) {
    if (token.empty()) return E_TOKEN_EMPTY;
    if (sk.empty()) return E_SK_EMPTY;
    
    rapidjson::Document doc;
    string err_msg;
    int ret = TokenToJson(token, doc, err_msg);
    if (ret != E_OK) return ret;

    // rapidjson::StringBuffer sb;
    // rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(sb);
    // doc.Accept(writer);
    // std::cout << sb.GetString() << std::endl;

    string ver = GetStringFromJsonDoc(doc, "ver");
    string appid = GetStringFromJsonDoc(doc, "appid");
    string uid = GetStringFromJsonDoc(doc, "uid");
    string sig = GetStringFromJsonDoc(doc, "sig");
    string skver = GetStringFromJsonDoc(doc, "skver");
    uint32_t expire = GetUint32FromJsonDoc(doc, "expire");
    uint32_t salt = GetUint32FromJsonDoc(doc, "salt");

    if (appid.empty() || ver.empty() || uid.empty() || sig.empty() || skver.empty() || expire == 0 || salt == 0) return E_TOKEN_MISS_FIELD;

    if (expire < time(NULL)) return E_TOKEN_EXPIRED;

    if (sig != GenSignatrue(appid, uid, salt, expire, skver, sk)) return E_TOKEN_INVALID;
    
    return 0;
}
