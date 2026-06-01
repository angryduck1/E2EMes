//
// Created by angryduck on 28.05.2026.
//

#include "client_activity.h"
#include <leveldb/db.h>

ClientActivity::ClientActivity(Session &session, Cryption &cryption, tcp::socket &socket, vector<unsigned char>& password_hash, vector<unsigned char>& public_key, vector<unsigned char>& private_key): session(session), cryption(cryption), socket(socket), password_hash(password_hash), public_key(public_key), private_key(private_key) {
    last_activity = std::chrono::steady_clock::now();

    main_thread();
}

void ClientActivity::update_activity() {
    lock_guard<mutex> lock(mtx);

    last_activity = std::chrono::steady_clock::now();
}

bool ClientActivity::time_out_activity() {
    lock_guard<mutex> lock(mtx);

    if (std::chrono::steady_clock::now() > last_activity + std::chrono::seconds(20)) {
        return true;
    }

    return false;
}

void ClientActivity::main_thread() {
    while (true) {
        try {
            if (time_out_activity()) {
                json heartbeat_json = {
                    {"status", "heartbeat"},
                    {"code", 500},
                    {"data", ""}
                };

                vector<unsigned char> heartbeat_data = pack_data(heartbeat_json);
                send_package(heartbeat_data, cryption, session, socket);

                cout << "Hearbeat send..." << endl;

                update_activity();
            }
        } catch (const system_error& e) {
            cout << "Client error: " << e.what() << endl;
        }
    }
}


