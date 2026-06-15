//
// Created by angryduck on 28.05.2026.
//

#include "client_activity.h"

ClientActivity::ClientActivity(Session &session, Cryption &cryption, tcp::socket &socket,
                               vector<unsigned char> &password_hash, vector<unsigned char> &public_key,
                               vector<unsigned char> &private_key) : session(session), cryption(cryption),
                                                                     socket(socket), password_hash(password_hash),
                                                                     public_key(public_key), private_key(private_key) {
    last_activity = std::chrono::steady_clock::now();

    newInput = false;
    running = true;
    input_text = "";
}

ClientActivity::~ClientActivity() {
    for (auto &i: general_keys) {
        sodium_memzero(i.second.data(), i.second.size());
    }
    general_keys.clear();

    if (!password_hash.empty()) {
        sodium_memzero(password_hash.data(), password_hash.size());
    }
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
    if (std::chrono::steady_clock::now() > last_sync_activity + std::chrono::seconds(5)) {
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

User ClientActivity::get_last_message_from_bd(const string &name_init, const string &name_recp) {
    auto &storage = get_storage();

    auto messages = storage.get_all<User>(
        where(
            or_(
                and_(c(&User::sender_name) == name_init, c(&User::recp_name) == name_recp),
                and_(c(&User::sender_name) == name_recp, c(&User::recp_name) == name_init)
            )
        ),
        order_by(&User::message_id).desc(),
        limit(1)
    );

    if (!messages.empty()) {
        return messages.front();
    }

    return {0};
}

void ClientActivity::add_new_message_to_bd(const string &name_init, const string &name_recp, const string &message,
                                           const string &nonce, int &message_id, time_t &time) {
    auto &storage = get_storage();

    User message_info = {0, message_id, time, name_init, name_recp, message, nonce};

    storage.insert(message_info);

    storage.sync_schema();
}

void ClientActivity::init_new_chat(const string &name) {
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
    } else {
        cout << name << " doesn`t exist on a server." << endl;
    }
}

void ClientActivity::send_new_message(const string &name) {
    json new_message_json = {
        {"status", "new_message"},
        {"code", 800},
        {"data", {{"name", name}}}
    };

    vector<unsigned char> new_message_data = pack_data(new_message_json);

    send_package(new_message_data, cryption, session, socket);

    vector<unsigned char> new_message_info = recv_package(cryption, session, socket);

    json new_message_info_json = nlohmann::json::parse(new_message_info);

    if (new_message_info_json["status"] != "new_message_failed") {
        string message;
        cout << "Type message: " << endl;
        std::getline(cin, message);

        if (!check_exist_gen_key("gen_key_" + name + ".data")) {
            cout << "Failed send new message to " << name << " because sync has not occurred yet";
        } else {
            if (!general_keys.contains(name)) {
                general_keys[name] = load_secret_initial("gen_key_" + name + ".data", password_hash);
            }

            vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
            randombytes_buf(nonce.data(), crypto_secretbox_NONCEBYTES);

            vector<unsigned char> crypted_message = cryption_message(message, nonce, general_keys[name]);

            string string_crypted_message = hex_to_string_convert_message(crypted_message);
            string string_nonce = hex_to_string_convert_message(nonce);

            json new_message_json = {
                {"status", "new_message_info"},
                {"code", 800},
                {"data", {{"message", string_crypted_message}, {"nonce", string_nonce}}}
            };

            vector<unsigned char> new_message_data = pack_data(new_message_json);

            send_package(new_message_data, cryption, session, socket);

            vector<unsigned char> new_message_help_data = recv_package(cryption, session, socket);

            json new_message_help_json = nlohmann::json::parse(new_message_help_data.begin(),
                                                               new_message_help_data.end());

            time_t time = new_message_help_json["data"]["time"];
            int message_id = new_message_help_json["data"]["message_id"];
            string name_init = new_message_help_json["data"]["name_init"];

            add_new_message_to_bd(name_init, name, string_crypted_message, string_nonce, message_id, time);
        }
    } else {
        cout << "You don`t have general chat with " << name << endl;
    }
}

void ClientActivity::sync_cloud() {
    running = false;

    json sync_json = {
        {"status", "sync_cloud"},
        {"code", 700},
        {"data", ""}
    };

    vector<unsigned char> sync_data = pack_data(sync_json);
    send_package(sync_data, cryption, session, socket);

    //cout << "New chats cloud sync..." << endl;

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
        for (auto const &user: new_chats_queue_json["data"]) {
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
            } else {
                status_info["status"] = "n";
            }

            sync_status["data"].push_back(status_info);
        }

        //cout << "Successful sync new chats with cloud" << endl;

        vector<unsigned char> sync_status_data = pack_data(sync_status);
        send_package(sync_status_data, cryption, session, socket);

        //cout << "Chat list sync..." << endl;

        json sync_chats_json = {
            {"status", "sync_chats"},
            {"code", 700},
            {"data", ""}
        };

        sync_chats_json["data"] = json::array();

        vector<unsigned char> chat_list_data = recv_package(cryption, session, socket);
        json chat_list_json = nlohmann::json::parse(chat_list_data.begin(), chat_list_data.end());

        if (chat_list_json["data"].is_array()) {
            for (auto const &user: chat_list_json["data"]) {
                string name = user["name"];
                string public_key_string = user["public_key"];

                string name_init = user["name_init"];

                int last_message_id = get_last_message_from_bd(name_init, name).message_id;
                int last_message_sync_id = user["message_id"];

                if (!check_exist_gen_key("gen_key_" + name + ".data")) {
                    vector<unsigned char> public_key = convert_public_key(public_key_string);

                    generate_secret_initial("gen_key_" + name + ".data", password_hash, private_key, public_key);
                }

                if (last_message_id < last_message_sync_id) {
                    json user_info;

                    user_info["name"] = name;
                    user_info["last_message_id"] = last_message_id;
                    user_info["message_id"] = last_message_sync_id;

                    sync_chats_json["data"].push_back(user_info);
                }

                if (!general_keys.contains(name)) {
                    general_keys[name] = load_secret_initial("gen_key_" + name + ".data", password_hash);
                }
            }
        }

        vector<unsigned char> chat_sync_data = pack_data(sync_chats_json);
        send_package(chat_sync_data, cryption, session, socket);

        bool is_end = false;

        while (!is_end) {
            vector<unsigned char> sync_chat_data = recv_package(cryption, session, socket);
            json sync_chat_json = nlohmann::json::parse(sync_chat_data.begin(), sync_chat_data.end());

            if (sync_chat_json["status"] == "end_sync_chats") {
                is_end = true;
                break;
            }

            string message = sync_chat_json["data"]["message"];
            string nonce = sync_chat_json["data"]["nonce"];
            string name_init = sync_chat_json["data"]["name_init"];
            string name_recp = sync_chat_json["data"]["name_recp"];
            string my_name = sync_chat_json["data"]["my_name"];
            int message_id = sync_chat_json["data"].value("message_id", 0);
            time_t time = sync_chat_json["data"].value("time", 0);

            add_new_message_to_bd(name_init, name_recp, message, nonce, message_id, time);

            cout << "Successful sync message_id " << message_id << " : " << name_init << " with " << name_recp << endl;

            vector<unsigned char> message_hex = convert_message(message);
            vector<unsigned char> nonce_hex = convert_message(nonce);

            string partner_name = "";

            if (name_init != my_name) {
                partner_name = name_init;
            } else if (name_recp != my_name) {
                partner_name = name_recp;
            }

            string message_text = decryption_message(message_hex, nonce_hex, general_keys[partner_name]);

            cout << message_text << endl;
        }

        json sync_status_json = {
            {"status", "sync_status"},
            {"code", 700},
            {"data", {}}
        };

        vector<unsigned char> sync_status_new_data = pack_data(sync_status_json);
        send_package(sync_status_new_data, cryption, session, socket);

        vector<unsigned char> sync_status_user_data = recv_package(cryption, session, socket);
        json sync_status_user_json = nlohmann::json::parse(sync_status_user_data.begin(), sync_status_user_data.end());

        if (sync_status_user_json["data"].is_array()) {
            for (auto const &user: sync_status_user_json["data"]) {
                string name = user["name"];
                string status = user["status"];

                cout << "Current status " << name << " : " << status << endl;
            }
        }

        update_sync_activity();
        running = true;
    } else {
        throw runtime_error("Failed sync with a server");
    }
}

void ClientActivity::main_thread() {
    thread worker(&ClientActivity::input_thread, this);
    worker.detach();

    init_bd("chats.bd");

    while (true) {
        try {
            if (newInput) {
                lock_guard<mutex> lock(input_mutex);

                string command = "";
                string argument = "";

                if (!input_text.empty()) {
                    stringstream ss(input_text);

                    ss >> command;

                    getline(ss >> ws, argument);
                }

                running = false;
                if (command == "/newChat" && !argument.empty()) {
                    size_t pos = argument.find_first_not_of(' ');

                    string name = argument;

                    if (pos != std::string::npos) {
                        name = argument.substr(pos);
                    }

                    update_activity();

                    init_new_chat(name);

                    cout << "Request on creating new chat was successful send!" << endl;
                }

                if (command == "/newMes" && !argument.empty()) {
                    size_t pos = argument.find_first_not_of(' ');

                    string name = argument;

                    if (pos != std::string::npos) {
                        name = argument.substr(pos);
                    }

                    update_activity();

                    send_new_message(name);

                    cout << "Request on sending new message was successful send!" << endl;
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
                send_package(heartbeat_data, cryption, session, socket);

                //cout << "Hearbeat send..." << endl;

                update_activity();
            }

            if (time_out_sync_activity()) {
                sync_cloud();
            }
        } catch (const system_error &e) {
            cout << "Client error: " << e.what() << endl;
        } catch (const exception &e) {
            cout << "Client error: " << e.what() << endl;
        }
    }
}
