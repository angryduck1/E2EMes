#include <iostream>
#include <sodium.h>
#include <boost/asio.hpp>
#include "cryption.h"
#include <thread>
#include <fstream>
#include <nlohmann/json.hpp>
#include "connections.h"
#include <sw/redis++/redis++.h>

using namespace std;
using namespace boost::asio;
using namespace sw::redis;

using ip::tcp;

using json = nlohmann::json;

void save_binary_key(const string& file_name, const unsigned char* key, size_t key_len) {
    ofstream file(file_name, ios::out | ios::binary);
    if (!file) {
        cerr << "Error opening file to save key" << endl;
    }

    file.write(reinterpret_cast<const char*>(key), key_len);
}

int load_binary_key(const string& file_name, unsigned char* key, size_t key_len) {
    ifstream file(file_name, ios::in | ios::binary);

    if (!file.is_open()) {
        cerr << "Error opening file to load key" << endl;
        return -1;
    }

    file.read(reinterpret_cast<char*>(key), key_len);

    return 0;
}

vector<unsigned char> pack_data(json data_json) {
    string data_str = data_json.dump();

    vector<unsigned char> data(data_str.begin(), data_str.end());

    return data;
}

string generate_session_token() {
    const size_t BASE_TOKEN_LEN = 48;
    const size_t VARIANT = sodium_base64_VARIANT_URLSAFE_NO_PADDING;

    const size_t B64_LEN = sodium_base64_ENCODED_LEN(BASE_TOKEN_LEN, VARIANT);

    unsigned char bin_buffer[BASE_TOKEN_LEN];
    string b64_buffer(B64_LEN, '\0');

    randombytes_buf(bin_buffer, BASE_TOKEN_LEN);

    sodium_bin2base64(b64_buffer.data(), B64_LEN, bin_buffer, BASE_TOKEN_LEN, VARIANT);

    if (!b64_buffer.empty() && b64_buffer.back() == '\0') {
        b64_buffer.pop_back();
    }

    return b64_buffer;
}

string generate_chat_id() {
    const size_t BASE_TOKEN_LEN = 12;
    const size_t VARIANT = sodium_base64_VARIANT_URLSAFE_NO_PADDING;

    const size_t B64_LEN = sodium_base64_ENCODED_LEN(BASE_TOKEN_LEN, VARIANT);

    unsigned char bin_buffer[BASE_TOKEN_LEN];
    string b64_buffer(B64_LEN, '\0');

    randombytes_buf(bin_buffer, BASE_TOKEN_LEN);

    sodium_bin2base64(b64_buffer.data(), B64_LEN, bin_buffer, BASE_TOKEN_LEN, VARIANT);

    if (!b64_buffer.empty() && b64_buffer.back() == '\0') {
        b64_buffer.pop_back();
    }

    return b64_buffer;
}

void add_session_to_bd(const string& session_id, const string& chat_id, Redis& redis) {
    redis.hset("sessions:" + session_id, "chat_id", chat_id);
}

void add_user_info_to_bd(const string& password, const string& name, const string& chat_id, const string& session_id, Redis& redis) {
    redis.hset("chat_ids:" + chat_id, "name", name);
    redis.hset("chat_ids:" + chat_id, "password", password);

    redis.sadd("status:" + chat_id, session_id);

    redis.set("names:" + name, chat_id);
}

int check_valid_session(const string& session_id, Redis& redis) {
    if (redis.exists(session_id)) {
        return 0;
    } else {
        return -1;
    }
}

void login(shared_ptr<tcp::socket> socket, Cryption& cryption, Connections& connections, Redis& redis) {
    std::vector<unsigned char> client_pk(crypto_kx_PUBLICKEYBYTES);
    read(*socket, buffer(client_pk));

    Session session = cryption.generate_server_session_keypair(client_pk.data());

    cout << "Successful creating session" << endl;

    json log_id = {
        {"status", "get_id"},
        {"code", 100},
        {"data", ""}
    };

    vector<unsigned char> log_id_data = pack_data(log_id);

    connections.send_package(log_id_data, cryption, session, *socket);

    vector<unsigned char> log_id_data_resp = connections.recv_package(cryption, session, *socket);
    json log_id_data_resp_json = nlohmann::json::parse(log_id_data_resp.begin(), log_id_data_resp.end());

    if (log_id_data_resp_json["code"] == 200 && log_id_data_resp_json["status"] == "new_id") {
        string new_session_id = generate_session_token();
        string new_chat_id = generate_chat_id();

        connections.add_session(new_session_id, socket, session);

        add_session_to_bd(new_session_id, new_chat_id, redis);

        json new_token_id_json = {
            {"status", "new_id"},
            {"code", 200},
            {"data", { {"id", new_session_id} }}
        };

        vector<unsigned char> new_token_id_json_send = pack_data(new_token_id_json);
        connections.send_package(new_token_id_json_send, cryption, session, *socket);

        vector<unsigned char> user_info = connections.recv_package(cryption, session, *socket);
        json user_info_json = nlohmann::json::parse(user_info.begin(), user_info.end());

        if (user_info_json["data"].contains("name") && user_info_json["data"].contains("password") && user_info_json["status"] == "user_info") {
            string password = user_info_json["data"]["password"];
            string name = user_info_json["data"]["name"];

            add_user_info_to_bd(password, name, new_chat_id, new_session_id, redis);

            json created_account = {
                {"status", "created_account"},
                {"code", 200},
                {"data", ""}
            };

            vector<unsigned char> created_account_send = pack_data(created_account);
            connections.send_package(created_account_send, cryption, session, *socket);
        } else {
            json created_account = {
                {"status", "created_account"},
                {"code", 300},
                {"data", ""}
            };

            vector<unsigned char> created_account_send = pack_data(created_account);
            connections.send_package(created_account_send, cryption, session, *socket);

            throw exception("Invalid signature user_info");
        }
    } else if (log_id_data_resp_json["code"] == 200 && log_id_data_resp_json["status"] == "current_id") {
        string token_id = log_id_data_resp_json["data"]["id"];

        json resp_token_id_json = {
            {"status", "status_id"},
            {"code", 200},
            {"data", ""}
        };

        if (check_valid_session(token_id, redis) != 0) {
            resp_token_id_json["code"] = 300;

            vector<unsigned char> resp_token_id_json_send = pack_data(resp_token_id_json);
            connections.send_package(resp_token_id_json_send, cryption, session, *socket);

            return;
        }

        connections.add_session(token_id, socket, session);

        vector<unsigned char> resp_token_id_json_send = pack_data(resp_token_id_json);
        connections.send_package(resp_token_id_json_send, cryption, session, *socket);
    } else if (log_id_data_resp_json["code"] == 200 && log_id_data_resp_json["status"] == "user_info_login") {
        string password = log_id_data_resp_json["data"]["password"];
        string name = log_id_data_resp_json["data"]["name"];

        if (redis.exists("names:"+name)) {
            string chat_id = *redis.get("names:"+name);
            string password_chat_id = *redis.hget("chat_ids:" + chat_id, "password");

            int attempts = 3;

            while (attempts > 0) {
                if (password != password_chat_id) {
                    json reply_message_json = {
                        {"status", "reply_message"},
                        {"code", 400},
                        {"data", "You have " + to_string(attempts) + " attempts"}
                    };

                    vector<unsigned char> reply_message_send = pack_data(reply_message_json);
                    connections.send_package(reply_message_send, cryption, session, *socket);

                    attempts -= 1;

                    vector<unsigned char> retry_login = connections.recv_package(cryption, session, *socket);
                    json retry_login_json = nlohmann::json::parse(retry_login);

                    password = retry_login_json["data"]["password"];
                } else {
                    break;
                }
            }

            if (attempts == 0) {
                json login_message_json = {
                    {"status", "login_message"},
                    {"code", 300},
                    {"data", ""}
                };

                vector<unsigned char> login_message_send = pack_data(login_message_json);
                connections.send_package(login_message_send, cryption, session, *socket);
            } else {
                json login_message_json = {
                    {"status", "login_message"},
                    {"code", 200},
                    {"data", ""}
                };

                vector<unsigned char> login_message_send = pack_data(login_message_json);
                connections.send_package(login_message_send, cryption, session, *socket);

                string new_session_id = generate_session_token();

                connections.add_session(new_session_id, socket, session);

                add_session_to_bd(new_session_id, chat_id, redis);
                redis.sadd("status:" + chat_id, new_session_id);

                json new_token_id_json = {
                    {"status", "new_id"},
                    {"code", 200},
                    {"data", { {"id", new_session_id} }}
                };

                vector<unsigned char> new_token_id_json_send = pack_data(new_token_id_json);
                connections.send_package(new_token_id_json_send, cryption, session, *socket);
            }
        } else {
            json reply_message_json = {
                {"status", "reply_message"},
                {"code", 300},
                {"data", ""}
            };

            vector<unsigned char> reply_message_send = pack_data(reply_message_json);
            connections.send_package(reply_message_send, cryption, session, *socket);
        }
    }
    else {
        throw exception("Invalid signature session authorize");
    }
}

int main() {
    if (sodium_init() < 0) {
        cerr << "Error init sodium! " << endl;
        return -1;
    }

    Cryption cryption;

    Connections connections;

    if (load_binary_key("open_key.bin", cryption.pk, crypto_kx_PUBLICKEYBYTES) != 0) {
        cerr << "Failed read PK" << endl;
    }

    if (load_binary_key("secret_key.bin", cryption.sk, crypto_kx_SECRETKEYBYTES) != 0) {
        cerr << "Failed read SK" << endl;
    }

    Redis redis("tcp://127.0.0.1:6400");

    io_context io_ctx;

    tcp::endpoint endpoint(ip::address_v4::any(), 8088);

    tcp::acceptor acceptor(io_ctx, endpoint);

    cout << "Server is listening on port 8088" << endl;

    while (true) {
        try {
            tcp::socket socket(io_ctx);
            acceptor.accept(socket);

            auto sock_ptr = make_shared<tcp::socket>(std::move(socket));

            thread new_session_thread([&, sock_ptr]() {
                try {
                    login(sock_ptr, cryption, connections, redis);
                } catch (const exception& e) {
                    cout << "Error: " << e.what() << endl;
                } catch (...) {
                    cout << "Unknown error" << endl;
                }
            });

            new_session_thread.detach();
        } catch (const system_error& e) {
            cout << "Server error: " << e.what() << endl;
        }
    }

    return 0;
}