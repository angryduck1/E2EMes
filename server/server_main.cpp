#include <iostream>
#include <sodium.h>
#include <boost/asio.hpp>
#include "../cryption.h"
#include <thread>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>
#include <chrono>
#include "connections.h"

using namespace std;
using namespace boost::asio;
using namespace sqlite_orm;
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

    if (file.gcount() != static_cast<streamsize>(key_len)) {
        cerr << "Key file " << file_name << " is too short" << endl;
        return -1;
    }

    return 0;
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

bool is_valid_name(const string& name) {
    if (name.size() < 3 || name.size() > 32) {
        return false;
    }

    // Names end up in client file names (gen_key_<name>.data), so keep them strictly alphanumeric.
    for (char ch : name) {
        if (!isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-') {
            return false;
        }
    }

    return name != "EMPTY_CHAT_ID" && name != "EMPTY_SESSION_ID";
}

string hash_password(const string& password) {
    char hash[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str(hash, password.data(), password.size(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw runtime_error("Failed to hash password");
    }

    return string(hash);
}

bool verify_password(const string& password, const string& stored, const string& chat_id, Redis& redis) {
    if (stored.rfind("$argon2", 0) == 0) {
        return crypto_pwhash_str_verify(stored.c_str(), password.data(), password.size()) == 0;
    }

    // Accounts created before hashing was introduced keep a plain password: check it in constant time and upgrade.
    bool ok = stored.size() == password.size() && sodium_memcmp(stored.data(), password.data(), stored.size()) == 0;

    if (ok) {
        redis.hset("chat_ids:" + chat_id, "password", hash_password(password));
    }

    return ok;
}

void add_session_to_bd(const string& session_id, const string& chat_id, Redis& redis) {
    redis.hset("sessions:" + session_id, "chat_id", chat_id);
}

void add_user_info_to_bd(const string& password, const string& name, const string& chat_id, const string& session_id, const string& hex_salt, const string& public_key, Redis& redis) {
    redis.hset("chat_ids:" + chat_id, "name", name);
    redis.hset("chat_ids:" + chat_id, "password", hash_password(password));
    redis.hset("chat_ids:" + chat_id, "salt", hex_salt);
    redis.hset("chat_ids:" + chat_id, "public_key", public_key);

    redis.sadd("status:" + chat_id, "EMPTY_SESSION_ID");
    redis.sadd("status:" + chat_id, session_id);

    redis.sadd("new_chat_queue:" + chat_id, "EMPTY_CHAT_ID");

    redis.sadd("chat_list:" + chat_id, "EMPTY_CHAT_ID");

    redis.sadd("chats_ids_сounter", chat_id);
}

void clear_sessions(Redis& redis) {
    vector<string> keys;

    redis.smembers("chats_ids_сounter", inserter(keys, keys.end()));

    if (!keys.empty()) {
        for (string& chat_id : keys) {
            vector<string> members_status;

            redis.smembers("status:"+chat_id, inserter(members_status, members_status.end()));

            if (!members_status.empty()) {
                for (string& member : members_status) {
                    if (member != "EMPTY_SESSION_ID") {
                        redis.srem("status:"+chat_id, member);

                        cout << "Clear " << member << endl;
                    }
                }
            }
        }
    }
}

void increment_users_counter(Redis& redis) {
    redis.incr("users_counter");
}

int check_valid_session(const string& session_id, Redis& redis) {
    if (redis.exists("sessions:"+session_id)) {
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

    vector<unsigned char> log_id_data = connections.pack_data(log_id);

    connections.send_package(log_id_data, cryption, session, *socket);

    vector<unsigned char> log_id_data_resp = connections.recv_package(cryption, session, *socket);
    json log_id_data_resp_json = nlohmann::json::parse(log_id_data_resp.begin(), log_id_data_resp.end());

    if (log_id_data_resp_json["code"] == 200 && log_id_data_resp_json["status"] == "new_id") {
        unsigned char server_salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(server_salt, crypto_pwhash_SALTBYTES);

        string hex_salt(crypto_pwhash_SALTBYTES * 2, ' ');
        sodium_bin2hex(&hex_salt[0], hex_salt.size() + 1, server_salt, crypto_pwhash_SALTBYTES);

        string new_session_id = generate_session_token();
        string new_chat_id = generate_chat_id();

        json new_token_id_json = {
            {"status", "new_id"},
            {"code", 200},
            {"data", { {"id", new_session_id}, {"salt", hex_salt} }}
        };

        vector<unsigned char> new_token_id_json_send = connections.pack_data(new_token_id_json);
        connections.send_package(new_token_id_json_send, cryption, session, *socket);

        vector<unsigned char> user_info = connections.recv_package(cryption, session, *socket);
        json user_info_json = nlohmann::json::parse(user_info.begin(), user_info.end());

        if (user_info_json["data"].contains("name") && user_info_json["data"].contains("password") && user_info_json["data"].contains("public_key") && user_info_json["status"] == "user_info") {
            string password = user_info_json["data"]["password"];
            string name = user_info_json["data"]["name"];
            string public_key = user_info_json["data"]["public_key"];

            int attempts = 5;

            // SETNX reserves the name atomically, so two registrations can't grab the same name
            // and an existing account can't be overwritten.
            while (!is_valid_name(name) || !redis.setnx("names:" + name, new_chat_id)) {
                if (attempts == 0) {
                    json timeout_message = {
                        {"status", "timeout_exceeded"},
                        {"code", 300},
                        {"data", "This name already exists"}
                    };

                    vector<unsigned char> timeout_message_send = connections.pack_data(timeout_message);

                    connections.send_package(timeout_message_send, cryption, session, *socket);

                    return;
                }

                json created_account = {
                    {"status", "retype_name"},
                    {"code", 200},
                    {"data", "This name already exists or is invalid (3-32 symbols: a-z, 0-9, _ or -). " + to_string(attempts) + " left."}
                };

                vector<unsigned char> created_account_send = connections.pack_data(created_account);
                connections.send_package(created_account_send, cryption, session, *socket);

                vector<unsigned char> user_info = connections.recv_package(cryption, session, *socket);
                json user_info_json = nlohmann::json::parse(user_info.begin(), user_info.end());

                name = user_info_json.at("data").at("name");

                --attempts;

                this_thread::sleep_for(std::chrono::seconds(4));
            }

            connections.add_session(new_session_id, socket, session);

            add_session_to_bd(new_session_id, new_chat_id, redis);

            add_user_info_to_bd(password, name, new_chat_id, new_session_id, hex_salt, public_key, redis);

            json created_account = {
                {"status", "created_account"},
                {"code", 200},
                {"data", ""}
            };

            vector<unsigned char> created_account_send = connections.pack_data(created_account);
            connections.send_package(created_account_send, cryption, session, *socket);

            increment_users_counter(redis);

            connections.client_thread(new_session_id, cryption, session, socket, redis);
        } else {
            json created_account = {
                {"status", "created_account"},
                {"code", 300},
                {"data", ""}
            };

            vector<unsigned char> created_account_send = connections.pack_data(created_account);
            connections.send_package(created_account_send, cryption, session, *socket);

            throw runtime_error("Invalid signature user_info");
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

            vector<unsigned char> resp_token_id_json_send = connections.pack_data(resp_token_id_json);
            connections.send_package(resp_token_id_json_send, cryption, session, *socket);

            return;
        }

        connections.add_session(token_id, socket, session);

        vector<unsigned char> resp_token_id_json_send = connections.pack_data(resp_token_id_json);
        connections.send_package(resp_token_id_json_send, cryption, session, *socket);

        connections.client_thread(token_id, cryption, session, socket, redis);
    } else if (log_id_data_resp_json["code"] == 200 && log_id_data_resp_json["status"] == "user_info_login") {
        string password = log_id_data_resp_json["data"]["password"];
        string name = log_id_data_resp_json["data"]["name"];

        auto chat_id_opt = redis.get("names:" + name);
        auto password_chat_id = chat_id_opt ? redis.hget("chat_ids:" + *chat_id_opt, "password") : OptionalString();

        if (chat_id_opt && password_chat_id) {
            string chat_id = *chat_id_opt;

            int attempts = 3;

            bool password_ok = verify_password(password, *password_chat_id, chat_id, redis);

            while (!password_ok && attempts > 0) {
                json reply_message_json = {
                    {"status", "reply_message"},
                    {"code", 400},
                    {"data", "You have " + to_string(attempts) + " attempts"}
                };

                vector<unsigned char> reply_message_send = connections.pack_data(reply_message_json);
                connections.send_package(reply_message_send, cryption, session, *socket);

                attempts -= 1;

                vector<unsigned char> retry_login = connections.recv_package(cryption, session, *socket);
                json retry_login_json = nlohmann::json::parse(retry_login);

                password = retry_login_json.at("data").at("password");

                password_ok = verify_password(password, *password_chat_id, chat_id, redis);
            }

            if (!password_ok) {
                json login_message_json = {
                    {"status", "login_message"},
                    {"code", 300},
                    {"data", ""}
                };

                vector<unsigned char> login_message_send = connections.pack_data(login_message_json);
                connections.send_package(login_message_send, cryption, session, *socket);
            } else {
                json login_message_json = {
                    {"status", "login_message"},
                    {"code", 200},
                    {"data", ""}
                };

                vector<unsigned char> login_message_send = connections.pack_data(login_message_json);
                connections.send_package(login_message_send, cryption, session, *socket);

                string new_session_id = generate_session_token();

                connections.add_session(new_session_id, socket, session);

                add_session_to_bd(new_session_id, chat_id, redis);
                redis.sadd("status:" + chat_id, new_session_id);

                string hex_salt = redis.hget("chat_ids:" + chat_id, "salt").value_or("");
                string public_key = redis.hget("chat_ids:" + chat_id, "public_key").value_or("");

                json new_token_id_json = {
                    {"status", "new_id"},
                    {"code", 200},
                    {"data", { {"id", new_session_id}, {"salt", hex_salt}, {"public_key", public_key} }}
                };

                vector<unsigned char> new_token_id_json_send = connections.pack_data(new_token_id_json);
                connections.send_package(new_token_id_json_send, cryption, session, *socket);

                connections.client_thread(new_session_id, cryption, session, socket, redis);
            }
        } else {
            json reply_message_json = {
                {"status", "reply_message"},
                {"code", 300},
                {"data", ""}
            };

            vector<unsigned char> reply_message_send = connections.pack_data(reply_message_json);
            connections.send_package(reply_message_send, cryption, session, *socket);
        }
    }
    else {
        throw runtime_error("Invalid signature session authorize");
    }
}

void manage_sessions(Redis& redis, Connections& connections) {
    while (true) {
        this_thread::sleep_for(std::chrono::seconds(30));

        connections.clean_disconnected(redis);
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
        return -1;
    }

    if (load_binary_key("secret_key.bin", cryption.sk, crypto_kx_SECRETKEYBYTES) != 0) {
        cerr << "Failed read SK" << endl;
        return -1;
    }

    Redis redis("tcp://127.0.0.1:6400");

    connections.init_bd("users.bd");

    io_context io_ctx;

    tcp::endpoint endpoint(ip::address_v4::any(), 8088);

    tcp::acceptor acceptor(io_ctx, endpoint);

    cout << "Server is listening on port 8088" << endl;

    clear_sessions(redis);

    thread manager_thread(manage_sessions, ref(redis), ref(connections));

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

    manager_thread.join();

    return 0;
}