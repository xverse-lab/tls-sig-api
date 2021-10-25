#include "tls_token.h"
#include <iostream>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 6) {
        std::cout << "usage:\n" << argv[0] << "  appid  uid  expire  sk  sv_ver\n";
        return -1;
    }

    string appid = argv[1];
    string uid = argv[2];
    int expire = atoi(argv[3]);
    string sk = argv[4];
    string sk_ver = argv[5];

    string token, errmsg;
    int ret = GenToken(expire, appid, uid, sk, sk_ver, token, errmsg);
    if (ret != 0) {
        std::cout << "gen token failed, " << ret << ", " << errmsg << std::endl;
    } else {
        std::cout << token << std::endl;
    }
    return 0;
}
