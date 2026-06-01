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

string Connections::get_chat_id(const string &session_id, Redis &redis) {
    string chat_id = *redis.hget("sessions:" + session_id, "chat_id");

    return chat_id;
}

void Connections::update_activity(const string& session_id) {
    lock_guard<mutex> lock(mtx);

    sessionIds[session_id].last_activity = std::chrono::steady_clock::now();
}

void Connections::add_session(const string& session_id,  std::shared_ptr<tcp::socket> socket_ptr, Session& session) {
    lock_guard<mutex> lock(mtx);

    sessionIds[session_id] = {socket_ptr, session, std::chrono::steady_clock::now()};
}

int Connections::new_chat(const string& session_id, string name, Redis &redis) {
    if (redis.exists("names:"+name)) {
        string chat_id = *redis.get("names:" + name);
    }
}

void Connections::client_thread(const string& session_id, Cryption &cryption, Session &session, shared_ptr<tcp::socket> socket, Redis &redis) {
    update_activity(session_id);
    while (true) {
        try {
            vector<unsigned char> message = recv_package(cryption, session, *socket);
            update_activity(session_id);

            json message_json = nlohmann::json::parse(message.begin(), message.end());

            if (message_json["code"] != 500) {

            }
        } catch (const system_error& e) {
            cout << "Error connection: " << e.what() << endl;
            break;
        }
    }
}

void Connections::clean_disconnected(Redis& redis) {
    cout << "Cleaning dead sessions...." << endl;

    vector<string> sessions_to_remove;

    auto now = std::chrono::steady_clock::now();

    {
        lock_guard<mutex> lock(mtx);

        for (auto it = sessionIds.begin(); it != sessionIds.end(); ) {
            if (now > it->second.last_activity + std::chrono::seconds(30)) {
                cout << "Removing " << it->first << endl;

                boost::system::error_code ec;

                it->second.socket->shutdown(tcp::socket::shutdown_both, ec);
                it->second.socket->close(ec);

                sessions_to_remove.push_back(it->first);

                it = sessionIds.erase(it);
            } else {
                it++;
            }
        }
    }

    for (auto i : sessions_to_remove) {
        string chat_id = get_chat_id(i, redis);

        if (!chat_id.empty()) {
            redis.srem("status:"+chat_id, i);
        }
    }

    cout << "End Cleaning dead sessions." << endl;
}
