#ifndef E2EMES_CRYPTION_H
#define E2EMES_CRYPTION_H

#include <sodium.h>
#include <vector>

class Session {
public:
    unsigned char rx[crypto_kx_SESSIONKEYBYTES]; // recv client
    unsigned char tx[crypto_kx_SESSIONKEYBYTES]; // to client
};

class Cryption {
public:
    unsigned char pk[crypto_kx_PUBLICKEYBYTES]; // public key
    unsigned char sk[crypto_kx_SECRETKEYBYTES]; // secret key

    Cryption() = default;

    void generate_server_keypair();
    void generate_client_keypair();
    Session generate_server_session_keypair(const unsigned char client_pk[crypto_kx_PUBLICKEYBYTES]) const;
    Session generate_client_session_keypair(const unsigned char server_pk[crypto_kx_PUBLICKEYBYTES]) const;

    std::vector<unsigned char> encode(const std::vector<unsigned char>& message, const Session& session, unsigned char nonce[crypto_secretbox_NONCEBYTES]);
    std::vector<unsigned char> decode(const std::vector<unsigned char>& message, const Session& session, unsigned char nonce[crypto_secretbox_NONCEBYTES]);
};


#endif //E2EMES_CRYPTION_H
