cmake_minimum_required(VERSION 2.8)
project(tls_sig_api)

set(CMAKE_CXX_FLAGS "-std=c++0x")

if(UNIX)
    find_package(ZLIB REQUIRED)
    find_package(OpenSSL REQUIRED)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(UNIX)
    include_directories(
        third/rapidjson/include
        ${ZLIB_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        src
        )

    option(BUILD_SHARED "build tlstoken shared library" OFF)
    if(BUILD_SHARED)
        add_library(tlstoken SHARED src/tls_token.cpp)
    else()
        add_library(tlstoken src/tls_token.cpp)
    endif()

    target_link_libraries(tlstoken -lz ${OPENSSL_CRYPTO_LIBRARIES})
    
    add_executable(gen_token tool/gen_token.cpp)
    target_link_libraries(gen_token tlstoken -lz ${OPENSSL_CRYPTO_LIBRARIES})

    add_executable(verify_token tool/verify_token.cpp)
    target_link_libraries(verify_token tlstoken -lz ${OPENSSL_CRYPTO_LIBRARIES})
endif()

install(TARGETS tlstoken
	PERMISSIONS WORLD_READ OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE
	DESTINATION lib)
