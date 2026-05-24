//
// Created by angryduck on 24.05.2026.
//

#include "connections.h"

int Connections::send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket) {
    boost::system::error_code error;

    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    vector<unsigned char> encryption_message = cryption.encode(message, session, nonce);

    encryption_message.insert(encryption_message.begin(), begin(nonce), end(nonce));

    auto body_size = static_cast<uint32_t>(encryption_message.size());
    uint32_t network_size = htonl(body_size);

    unsigned char payload_size[4];

    memcpy(payload_size, &network_size, 4);

    encryption_message.insert(encryption_message.begin(), begin(payload_size), end(payload_size));

    write(socket, buffer(encryption_message), error);

    if (error) {
        cerr << "Error send packet to client" << endl;
        return -1;
    }

    return 0;
}

vector<unsigned char> Connections::recv_package(Cryption& cryption, Session& session, tcp::socket& socket) {
    try {
        vector<unsigned char> buf(4);

        read(socket, buffer(buf));

        uint32_t payload_size = 0;
        memcpy(&payload_size, buf.data(), 4);

        payload_size = ntohl(payload_size);

        if (payload_size < 4 + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES || payload_size > 1024) {
            cerr << "Invalid structure of payload" << endl;

            return {};
        }

        vector<unsigned char> payload(payload_size);

        read(socket, buffer(payload));

        unsigned char nonce[crypto_secretbox_NONCEBYTES];

        memcpy(nonce, payload.data(), crypto_secretbox_NONCEBYTES);

        payload.erase(payload.begin(), payload.begin() + crypto_secretbox_NONCEBYTES);

        vector<unsigned char> decrypted_message = cryption.decode(payload, session, nonce);

        return decrypted_message;
    } catch (const system_error& e) {
        cerr << "Network recv error: "<< e.what() << endl;
    }

    return {};
}

void Connections::add_session(string session_id,  std::shared_ptr<tcp::socket> socket_ptr, Session& session) {
    sessionIds[session_id] = make_pair(socket_ptr, session);
}


