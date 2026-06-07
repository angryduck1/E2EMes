//
// Created by angryduck on 28.05.2026.
//

#include "client_activity.h"
#include <leveldb/db.h>

ClientActivity::ClientActivity(Session &session, Cryption &cryption, tcp::socket &socket, vector<unsigned char>& password_hash, vector<unsigned char>& public_key, vector<unsigned char>& private_key): session(session), cryption(cryption), socket(socket), password_hash(password_hash), public_key(public_key), private_key(private_key) {
    last_activity = std::chrono::steady_clock::now();

    newInput = false;
    running = true;
    input_text = "";
}

void ClientActivity::update_activity() {
    lock_guard<mutex> lock(mtx);

    last_activity = std::chrono::steady_clock::now();
}

void ClientActivity::update_sync_activity() {
    last_sync_activity = std::chrono::steady_clock::now();
}

bool ClientActivity::time_out_activity() {
    lock_guard<mutex> lock(mtx);

    if (std::chrono::steady_clock::now() > last_activity + std::chrono::seconds(20)) {
        return true;
    }

    return false;
}

bool ClientActivity::time_out_sync_activity() {
    if (std::chrono::steady_clock::now() > last_sync_activity + std::chrono::seconds(40)) {
        return true;
    }

    return false;
}

void ClientActivity::input_thread() {
    while (true) {
        string temp;
        while (running && getline(cin, temp)) {
            lock_guard<mutex> lock(input_mutex);

            input_text = temp;
            newInput = true;
        }
    }
}

void ClientActivity::init_new_chat(const string& name) {
    json new_chat_recv_json = {
        {"status", "new_chat"},
        {"code", 600},
        {"data", {{"name", name}}}
    };

    vector<unsigned char> new_chat_recv = pack_data(new_chat_recv_json);

    send_package(new_chat_recv, cryption, session, socket);

    vector<unsigned char> new_chat_info = recv_package(cryption, session, socket);

    json new_chat_info_json = nlohmann::json::parse(new_chat_info);

    if (new_chat_info_json["status"] != "new_chat_failed") {
        vector<unsigned char> public_key = convert_public_key(new_chat_info_json["data"]["public_key"]);

        generate_secret_initial("gen_key_" + name + ".data", password_hash, private_key, public_key);
    }
    else {
        cout << name << " doesn`t exist on a server." << endl;
    }
}

void ClientActivity::main_thread() {
    thread worker(&ClientActivity::input_thread, this);
    worker.detach();

    while (true) {
        try {
            if (newInput) {
                lock_guard<mutex> lock(input_mutex);

                running = false;
                if (input_text.find("/newChat") != string::npos) {
                    string target = "/newChat";
                    size_t pos = input_text.find(target);

                    string name = input_text.substr(pos + target.length() + 1);

                    update_activity();

                    init_new_chat(name);

                    cout << "Request on creating new chat was successful send!" << endl;
                }
                running = true;
                newInput = false;
            }

            if (time_out_activity()) {
                json heartbeat_json = {
                    {"status", "heartbeat"},
                    {"code", 500},
                    {"data", ""}
                };

                vector<unsigned char> heartbeat_data = pack_data(heartbeat_json);
                send_package(heartbeat_data, cryption , session, socket);

                cout << "Hearbeat send..." << endl;

                update_activity();
            }

            if (time_out_sync_activity()) {
                running = false;

                json sync_json = {
                    {"status", "sync_cloud"},
                    {"code", 700},
                    {"data", ""}
                };

                vector<unsigned char> sync_data = pack_data(sync_json);
                send_package(sync_data, cryption , session, socket);

                cout << "New chats cloud sync..." << endl;

                vector<unsigned char> new_chats_queue_data = recv_package(cryption, session, socket);
                json new_chats_queue_json = nlohmann::json::parse(new_chats_queue_data.begin(), new_chats_queue_data.end());

                //cout << setw(4) << new_chats_queue_json << endl;

                json sync_status = {
                    {"status", "sync_ok"},
                    {"code", 700},
                    {"data", ""}
                };

                sync_status["data"] = json::array();

                if (new_chats_queue_json["data"].is_array()) {
                    for (auto const& user : new_chats_queue_json["data"]) {
                        json status_info;
                        string name = user["name"];

                        string q;
                        cout << "Do you wanna create a new chat with " << name << " (y/n)" << endl;
                        cin >> q;

                        status_info["name"] = name;

                        if (q == "y") {
                            status_info["status"] = "y";

                            string public_key_string = user["public_key"];

                            if (!check_exist_gen_key("gen_key_" + name + ".data")) {
                                vector<unsigned char> public_key = convert_public_key(public_key_string);

                                generate_secret_initial("gen_key_" + name + ".data", password_hash, private_key, public_key);
                            }
                        }

                        status_info["status"] = "n";

                        sync_status["data"].push_back(status_info);
                    }

                    cout << "Successful sync new chats with cloud" << endl;

                    vector<unsigned char> sync_status_data = pack_data(sync_status);
                    send_package(sync_status_data, cryption, session, socket);

                    cout << "Chat list sync..." << endl;

                    vector<unsigned char> chat_list_data = recv_package(cryption, session, socket);
                    json chat_list_json = nlohmann::json::parse(chat_list_data.begin(), chat_list_data.end());

                    if (chat_list_json["data"].is_array()) {
                        for (auto const& user : chat_list_json["data"]) {
                            string name = user["name"];
                            string public_key_string = user["public_key"];

                            if (!check_exist_gen_key("gen_key_" + name + ".data")) {
                                vector<unsigned char> public_key = convert_public_key(public_key_string);

                                generate_secret_initial("gen_key_" + name + ".data", password_hash, private_key, public_key);
                            }
                        }
                    }

                    update_sync_activity();
                    running = true;
                } else {
                    throw runtime_error("Failed sync with a server");
                }
            }
        } catch (const system_error& e) {
            cout << "Client error: " << e.what() << endl;
        } catch (const exception& e) {
            cout << "Client error: " << e.what() << endl;
        }
    }
}


