#include <iostream>
#include "cryption.h"
#include <vector>
#include <stdexcept>

using namespace std;

void Cryption::generate_server_keypair() {
    if (crypto_kx_keypair(pk, sk) != 0) {
        throw runtime_error("Error generate server keypair");
    }
}

void Cryption::generate_client_keypair() {
    if (crypto_kx_keypair(pk, sk) != 0) {
        throw runtime_error("Error generate client keypair");
    }
}

Session Cryption::generate_server_session_keypair(const unsigned char client_pk[crypto_kx_PUBLICKEYBYTES]) const {
    Session session;

    if (crypto_kx_server_session_keys(session.rx,  session.tx, pk, sk, client_pk) != 0) {
        throw runtime_error("Error generate server session keypair");
    }

    return session;
}

Session Cryption::generate_client_session_keypair(const unsigned char server_pk[crypto_kx_PUBLICKEYBYTES]) const {
    Session session;

    if (crypto_kx_client_session_keys(session.rx,  session.tx, pk, sk, server_pk) != 0) {
        throw runtime_error("Error generate client session keypair");
    }

    return session;
}

vector<unsigned char> Cryption::encode(const std::vector<unsigned char>& message, const Session& session, unsigned char nonce[crypto_secretbox_NONCEBYTES]) {
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    std::vector<unsigned char> encryption_message(crypto_secretbox_MACBYTES + message.size());

    crypto_secretbox_easy(encryption_message.data(), message.data(), message.size(), nonce, session.tx);

    return encryption_message;
}

vector<unsigned char> Cryption::decode(const std::vector<unsigned char>& message, const Session& session, unsigned char nonce[crypto_secretbox_NONCEBYTES]) {
   if (message.size() < crypto_secretbox_MACBYTES) {
       throw runtime_error("Message to decode is too low");
   }

    std::vector<unsigned char> decryption_message(message.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decryption_message.data(), message.data(), message.size(), nonce, session.rx) != 0) {
        throw runtime_error("Message is corrupted");
    }

    return decryption_message;
}