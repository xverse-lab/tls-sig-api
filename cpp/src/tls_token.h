#pragma once

#include <string>
#include <stdint.h>

using std::string;

enum {
    E_OK = 0,
    E_SK_EMPTY,                // sk为空
    E_SK_VER_EMPTY,            // sk version为空
    E_APPID_EMPTY,             // appid为空
    E_UID_EMPTY,               // uid为空
    E_EXPIRE_INVALID,          // 过期时间非法
    E_TOKEN_EMPTY,             // token为空
    E_COMPRESS_ERR,            // zip压缩失败
    E_UNCOMPRESS_ERR,          // zip解压失败
    E_ENCODE_ERR,              // base64 encode失败
    E_DECODE_ERR,              // base64 decode失败
    E_PARSE_ERR,               // json 解析失败
    E_TOKEN_MISS_FIELD,        // token字段缺失
    E_TOKEN_EXPIRED,           // token已过期
    E_TOKEN_INVALID,           // token无效，验签失败

    E_ERR_MAX,
};

/**
 * @brief 生成token
 * 
 * @param expire token有效期，如果有效期为24小时，则填24*3600
 * @param appid 应用ID(元象生成)
 * @param uid 用户id
 * @param sk 计算token用的加密密钥(元象生成)
 * @param sk_ver 密钥版本(元象生成)
 * @param token 返回生成的token
 * @param err_msg 返回错误信息
 * @return int 0表示成功，非0表示失败，失败信息在err_msg
 */
int GenToken(uint32_t expire, const string &appid, const string &uid, const string &sk, const string &sk_ver, string &token, string &err_msg);

/**
 * @brief 校验token是否有效
 * 
 * @param token 待校验的token
 * @param sk 校验token用的密钥(元象生成)
 * @return int 0表示token有效，非0表示token无效
 */
int VerifyToken(const string& token, const string &sk);