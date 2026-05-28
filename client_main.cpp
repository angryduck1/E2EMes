#include <iostream>
#include <sodium.h>
#include <boost/asio.hpp>
#include "cryption.h"
#include <stdint.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <sstream>

using namespace std;
using namespace boost::asio;

using ip::tcp;

using json = nlohmann::json;

int send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket) {
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

vector<unsigned char> recv_package(Cryption& cryption, Session& session, tcp::socket& socket) {
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

void save_session_token(const string& file_name, string token_id) {
    string password;

    while (true) {
        cout << "Enter the session password: " << endl;
        cin >> password;

        if (password.size() < 10) {
            cout << "Password is too low, need more than 10 symbols." << endl;
        } else {
            break;
        }
    }

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);

    vector <unsigned char> password_hash(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(password_hash.data(), password_hash.size(), password.data(), password.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw runtime_error("Memory overflow");
    }

    sodium_memzero(&password[0], password.size());

    vector<unsigned char> encrypted_session(token_id.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(encrypted_session.data(), reinterpret_cast<const unsigned char*>(token_id.data()), token_id.size(), nonce, password_hash.data());

    ofstream file(file_name, ios::out | ios::binary);

    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(nonce), crypto_secretbox_NONCEBYTES);
        file.write(reinterpret_cast<const char*>(salt), crypto_pwhash_SALTBYTES);
        file.write(reinterpret_cast<const char*>(encrypted_session.data()), encrypted_session.size());
    } else {
        throw runtime_error("Failed to save session token!");
    }

    file.close();
}

string load_session_token(const string& file_name) {
    ifstream file(file_name, ios::binary | ios::ate);

    if (!file.is_open()) {
        return "";
    }

    streamsize file_size = file.tellg();

    if (file_size < static_cast<streamsize>(crypto_secretbox_NONCEBYTES + crypto_pwhash_SALTBYTES + crypto_secretbox_MACBYTES)) {
        throw runtime_error("Invalid structure of session token!");
    }

    file.seekg(0, std::ios::beg);

    string password;
    cout << "Enter the session password: " << endl;
    cin >> password;

    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    vector <unsigned char> crypted_session(file_size - crypto_secretbox_NONCEBYTES - crypto_pwhash_SALTBYTES);

    file.read(reinterpret_cast<char*>(nonce), crypto_secretbox_NONCEBYTES);
    file.read(reinterpret_cast<char*>(salt), crypto_pwhash_SALTBYTES);
    file.read(reinterpret_cast<char*>(crypted_session.data()), crypted_session.size());

    vector <unsigned char> password_hash(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(password_hash.data(), password_hash.size(), password.data(), password.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw runtime_error("Memory overflow");
    }

    sodium_memzero(&password[0], password.size());

    vector <unsigned char> decrypted_session(crypted_session.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decrypted_session.data(), crypted_session.data(), crypted_session.size(), nonce, password_hash.data()) != 0) {
        throw runtime_error("Password is invalid!");
    }

    return string(decrypted_session.begin(), decrypted_session.end());
}

void login(Cryption& cryption, Session& session, tcp::socket& socket) {
    vector<unsigned char> get_log = recv_package(cryption, session, socket);

    json log = nlohmann::json::parse(get_log.begin(), get_log.end());

    if (log["status"] == "get_id" && log["code"] == 100) {
        string login_register;

        string token = load_session_token("session_token.data");
        if (token == "") {
            string login_register;

            cout << "Do you want register new account? (y/n): ";
            cin >> login_register;

            if (login_register == "y") {
                json new_token = {
                    {"status", "new_id"},
                    {"code", 200},
                    {"data", ""}
                };

                vector<unsigned char> new_token_data = pack_data(new_token);

                send_package(new_token_data, cryption, session, socket);

                vector<unsigned char> id_response = recv_package(cryption, session, socket);
                json id_json = nlohmann::json::parse(id_response.begin(), id_response.end());

                if (id_json["status"] == "new_id" && id_json["code"] == 200) {
                    string new_token_id = id_json["data"]["id"].get<string>();
                    save_session_token("session_token.data", new_token_id);
                    cout << "You will added to server! Welcome!" << endl;
                } else if (id_json["status"] == "new_id" && id_json["code"] == 300)  {
                    throw runtime_error("Failed adding you to server!");
                } else {
                    throw runtime_error("Invalid signature new_id");
                }

                string name = "angryduck";
                string password = "root";

                cout << "Enter name: " << endl;
                //cin >> name;

                cout << "Enter password: " << endl;
                //cin >> password;

                json user_info = {
                    {"status", "user_info"},
                    {"code", 200},
                    {"data", {{"name", name}, {"password", password}, }}
                };

                vector<unsigned char> user_info_data = pack_data(user_info);
                send_package(user_info_data, cryption, session, socket);

                vector<unsigned char> user_data_response = recv_package(cryption, session, socket);
                json user_data_response_json = nlohmann::json::parse(user_data_response);

                if (user_data_response_json["status"] == "created_account" && user_data_response_json["code"] == 200) {
                    cout << name << ", Your account was successful added to server!" << endl;
                }
            } else if (login_register == "n") {
                string name = "angryduck";
                string password = "root";

                cout << "Enter name: " << endl;
                //cin >> name;

                cout << "Enter password: " << endl;
                cin >> password;

                json user_info = {
                    {"status", "user_info_login"},
                    {"code", 200},
                    {"data", {{"name", name}, {"password", password}, }}
                };

                vector<unsigned char> user_info_data = pack_data(user_info);
                send_package(user_info_data, cryption, session, socket);

                bool accept = false;

                while (!accept) {
                    vector<unsigned char> login_message_response = recv_package(cryption, session, socket);
                    json login_message_response_json = nlohmann::json::parse(login_message_response);

                    if (login_message_response_json["code"] == 400) {
                        cout << login_message_response_json["data"] << " Try enter password again: " << endl;

                        string password_attempt;
                        cin >> password_attempt;

                        json user_info_attempt = {
                            {"status", "user_info_login"},
                            {"code", 200},
                            {"data", {{"name", name}, {"password", password_attempt}, }}
                        };

                        vector<unsigned char> user_info_data_attempt = pack_data(user_info_attempt);
                        send_package(user_info_data_attempt, cryption, session, socket);
                    } else if (login_message_response_json["code"] == 300) {
                        throw runtime_error("Entered password is incorrect");
                    } else if (login_message_response_json["code"] == 200) {
                        cout << name << ", welcome to account!" << endl;
                        accept = true;
                        break;
                    }
                }

                vector<unsigned char> id_response = recv_package(cryption, session, socket);
                json id_json = nlohmann::json::parse(id_response.begin(), id_response.end());

                if (id_json["status"] == "new_id" && id_json["code"] == 200) {
                    string new_token_id = id_json["data"]["id"].get<string>();
                    save_session_token("session_token.data", new_token_id);
                    cout << "You will added to server! Welcome!" << endl;
                }

            } else {
                throw runtime_error("Unknown answer");
            }
        } else {
            json current_token = {
                {"status", "user_info"},
                {"code", 200},
                {"data", {{"id", token}}}
            };

            vector<unsigned char> current_token_data = pack_data(current_token);

            send_package(current_token_data, cryption, session, socket);

            vector<unsigned char> id_response = recv_package(cryption, session, socket);
            json id_response_json = nlohmann::json::parse(id_response.begin(), id_response.end());

            if (id_response_json["status"] == "status_id" && id_response_json["code"] == 200) {
                cout << "You will added to server! Welcome!" << endl;
            } else if (id_response_json["status"] == "status_id" && id_response_json["code"] == 300) {
                cout << "Your token hasn`t been finded!" << endl;
            }
            else {
                throw runtime_error("Invalid signature id_response");
            }
        }
    }
}

int main() {
    if (sodium_init() < 0) {
        cerr << "Error init sodium! " << endl;
        return -1;
    }

    Cryption cryption;

    cryption.generate_client_keypair();

    unsigned char pk_server[crypto_kx_PUBLICKEYBYTES];

    load_binary_key("open_key.bin", pk_server, crypto_kx_PUBLICKEYBYTES);

    Session session = cryption.generate_client_session_keypair(pk_server);

    io_context io_ctx;

    tcp::endpoint endpoint(ip::make_address("127.0.0.1"), 8088);

    tcp::socket socket(io_ctx);

    try {
        socket.connect(endpoint);

        write(socket, buffer(cryption.pk));

        cout << "Successful send" << endl;

        login(cryption, session, socket);
    } catch (const system_error& e) {
        cout << "Client error: " << e.what() << endl;
    }
}