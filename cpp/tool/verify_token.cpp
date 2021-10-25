#include "tls_token.h"
#include <iostream>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cout << "usage:\n" << argv[0] << "  token  sk\n";
        return -1;
    }

    string token = argv[1];
    string sk = argv[2];

    int ret = VerifyToken(token, sk);
    if (ret != 0) {
        std::cout << "token verify failed, " << ret << std::endl;
    } else {
        std::cout << "token verify success" << std::endl;
    }
    return 0;
}
