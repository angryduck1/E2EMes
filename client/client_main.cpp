#include <iostream>
#include <sodium.h>
#include <boost/asio.hpp>
#include "../cryption.h"
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include "client_activity.h"
#include "client_connection.h"
#include "bip_39.h"

#include <QApplication>
#include <QFile>
#include <mainwindow.h>

using namespace std;
using namespace boost::asio;

using ip::tcp;

using json = nlohmann::json;

const int SESSION_SIZE = 64;
const int SEED_SIZE = 12;

struct SessionData {
    string session_id;
    vector<unsigned char> private_key;
    vector<unsigned char> public_key;
    vector<unsigned char> password_hash;
};

string bip_seed_generate() {
    string word_seed;

    for (int i = 0; i < SEED_SIZE; i++) {
        unsigned seed_id = randombytes_uniform(2048);
        string word = WORDLIST.at(seed_id);

        if (i + 1 == SEED_SIZE)
            word_seed += word;
        else {
            word_seed += word + " ";
        }
    }

    return word_seed;
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

SessionData save_session_token_master_key(const string& file_name, const string& token_id, vector<unsigned char>& salt_master) {
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

    vector<unsigned char> encrypted_session(token_id.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(encrypted_session.data(), reinterpret_cast<const unsigned char*>(token_id.data()), token_id.size(), nonce, password_hash.data());

    sodium_memzero(&password[0], password.size());

    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    string master_password = bip_seed_generate();

    cout << "Your master password is: " << master_password << " : save this!" << endl;

    vector <unsigned char> private_key(crypto_box_SECRETKEYBYTES);

    if (crypto_pwhash(private_key.data(), private_key.size(), master_password.data(), master_password.size(), salt_master.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw runtime_error("Memory overflow");
    }

    vector <unsigned char> public_key(crypto_box_PUBLICKEYBYTES);

    if (crypto_scalarmult_base(public_key.data(), private_key.data()) != 0) {
        throw runtime_error("Failed to generate public master key!");
    }

    vector<unsigned char> encrypted_private_key(private_key.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(encrypted_private_key.data(), reinterpret_cast<const unsigned char*>(private_key.data()), private_key.size(), nonce, password_hash.data());

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ofstream file(file_name, ios::out | ios::binary);

    sodium_memzero(&master_password[0], master_password.size());

    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(nonce), crypto_secretbox_NONCEBYTES);
        file.write(reinterpret_cast<const char*>(salt), crypto_pwhash_SALTBYTES);
        file.write(reinterpret_cast<const char*>(encrypted_session.data()), encrypted_session.size());
        file.write(reinterpret_cast<const char*>(encrypted_private_key.data()), encrypted_private_key.size());
        file.write(reinterpret_cast<const char*>(public_key.data()), crypto_box_PUBLICKEYBYTES);
    } else {
        throw runtime_error("Failed to save session token!");
    }

    //sodium_memzero(password_hash.data(), password_hash.size());

    file.close();

    return {token_id, private_key, public_key, password_hash};
}

SessionData save_session_token_load_master_key(const string& file_name, const string& token_id, vector<unsigned char>& salt_master, const vector<unsigned char>& public_key) {
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

    vector<unsigned char> encrypted_session(token_id.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(encrypted_session.data(), reinterpret_cast<const unsigned char*>(token_id.data()), token_id.size(), nonce, password_hash.data());

    sodium_memzero(&password[0], password.size());

    string master_password;

    cout << "Enter your master password: " << endl;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    getline(cin, master_password);

    vector <unsigned char> private_key(crypto_box_SECRETKEYBYTES);

    if (crypto_pwhash(private_key.data(), private_key.size(), master_password.data(), master_password.size(), salt_master.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw runtime_error("Memory overflow");
    }

    vector <unsigned char> public_key_check(crypto_box_PUBLICKEYBYTES);

    if (crypto_scalarmult_base(public_key_check.data(), private_key.data()) != 0) {
        throw runtime_error("Failed to generate public master key!");
    }

    if (sodium_memcmp(public_key.data(), public_key_check.data(), crypto_box_PUBLICKEYBYTES) != 0) {
        throw runtime_error("Public key is corrupted! Failed to login in account!");
    }

    vector<unsigned char> encrypted_private_key(private_key.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(encrypted_private_key.data(), reinterpret_cast<const unsigned char*>(private_key.data()), private_key.size(), nonce, password_hash.data());

    ofstream file(file_name, ios::out | ios::binary);

    sodium_memzero(&master_password[0], master_password.size());

    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(nonce), crypto_secretbox_NONCEBYTES);
        file.write(reinterpret_cast<const char*>(salt), crypto_pwhash_SALTBYTES);
        file.write(reinterpret_cast<const char*>(encrypted_session.data()), encrypted_session.size());
        file.write(reinterpret_cast<const char*>(encrypted_private_key.data()), encrypted_private_key.size());
        file.write(reinterpret_cast<const char*>(public_key_check.data()), crypto_box_PUBLICKEYBYTES);
    } else {
        throw runtime_error("Failed to save session token!");
    }

    //sodium_memzero(password_hash.data(), password_hash.size());

    file.close();

    return {token_id, private_key, public_key, password_hash};
}

SessionData load_session_token_master_key(const string& file_name) {
    ifstream file(file_name, ios::binary | ios::ate);

    if (!file.is_open()) {
        return {};
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

    vector <unsigned char> crypted_session(SESSION_SIZE + crypto_secretbox_MACBYTES);
    vector <unsigned char> crypted_private_key(crypto_box_SECRETKEYBYTES + crypto_secretbox_MACBYTES);
    vector <unsigned char> public_key(crypto_box_PUBLICKEYBYTES);

    file.read(reinterpret_cast<char*>(nonce), crypto_secretbox_NONCEBYTES);
    file.read(reinterpret_cast<char*>(salt), crypto_pwhash_SALTBYTES);
    file.read(reinterpret_cast<char*>(crypted_session.data()), crypted_session.size());
    file.read(reinterpret_cast<char*>(crypted_private_key.data()), crypted_private_key.size());
    file.read(reinterpret_cast<char*>(public_key.data()), public_key.size());

    vector <unsigned char> password_hash(crypto_secretbox_KEYBYTES);

    if (crypto_pwhash(password_hash.data(), password_hash.size(), password.data(), password.size(), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw runtime_error("Memory overflow");
    }

    sodium_memzero(&password[0], password.size());

    vector <unsigned char> decrypted_session(crypted_session.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decrypted_session.data(), crypted_session.data(), crypted_session.size(), nonce, password_hash.data()) != 0) {
        throw runtime_error("Password is invalid!");
    }

    vector <unsigned char> decrypted_private_key(crypted_private_key.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decrypted_private_key.data(), crypted_private_key.data(), crypted_private_key.size(), nonce, password_hash.data()) != 0) {
        throw runtime_error("Password is invalid!");
    }

    string session_id = string(decrypted_session.begin(), decrypted_session.end());

    //sodium_memzero(password_hash.data(), password_hash.size());

    SessionData session_data = {session_id, decrypted_private_key, public_key, password_hash};

    return session_data;
}

SessionData login(Cryption& cryption, Session& session, tcp::socket& socket) {
    vector<unsigned char> get_log = recv_package(cryption, session, socket);

    json log = nlohmann::json::parse(get_log.begin(), get_log.end());

    if (log["status"] == "get_id" && log["code"] == 100) {
        string login_register;

        SessionData token = load_session_token_master_key("session_token.data");
        if (token.session_id.empty()) {
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

                SessionData session_data;

                if (id_json["status"] == "new_id" && id_json["code"] == 200) {
                    string new_token_id = id_json["data"]["id"];
                    string salt_hex = id_json["data"]["salt"];

                    vector<unsigned char> salt_master = convert_salt(salt_hex);

                    session_data = save_session_token_master_key("session_token.data", new_token_id, salt_master);
                    cout << "Your token has been created!" << endl;
                } else if (id_json["status"] == "new_id" && id_json["code"] == 300)  {
                    throw runtime_error("Failed creating your token on server!");
                } else {
                    throw runtime_error("Invalid signature new_id");
                }

                string name;
                string password;

                cout << "Enter name: " << endl;
                cin >> name;

                cout << "Enter password: " << endl;
                cin >> password;

                string hex_public_key(crypto_box_PUBLICKEYBYTES * 2, ' ');
                sodium_bin2hex(&hex_public_key[0], hex_public_key.size() + 1, session_data.public_key.data(), crypto_box_PUBLICKEYBYTES);

                json user_info = {
                    {"status", "user_info"},
                    {"code", 200},
                    {"data", {{"name", name}, {"password", password}, {"public_key", hex_public_key}}}
                };

                vector<unsigned char> user_info_data = pack_data(user_info);
                send_package(user_info_data, cryption, session, socket);

                bool accept = false;

                while (!accept) {
                    vector<unsigned char> name_resp = recv_package(cryption, session, socket);
                    json name_resp_json = nlohmann::json::parse(name_resp);

                    if (name_resp_json["status"] == "retype_name") {
                        string retype_name;
                        cout << name_resp_json["data"] << endl;

                        cout << "Enter name: " << endl;
                        cin >> retype_name;

                        name = retype_name;

                        json name_info_json = {
                            {"status", "name_info"},
                            {"code", 200},
                            {"data", {{"name", retype_name}}}
                        };

                        vector<unsigned char> name_info = pack_data(name_info_json);
                        send_package(name_info, cryption, session, socket);
                    }
                    else if (name_resp_json["status"] == "timeout_exceeded") {
                        cout << "Attempts has been exceeded" << endl;

                        throw exception("Please, try to register again");
                    }
                    else if (name_resp_json["status"] == "created_account" && name_resp_json["code"] == 200) {
                        cout << name << ", Your account was successful added to server!" << endl;

                        accept = true;
                        break;
                    } else {
                        throw runtime_error("Error register account!");
                    }
                }

                return session_data;
            } else if (login_register == "n") {
                string name;
                string password;

                cout << "Enter name: " << endl;
                cin >> name;

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
                    string new_token_id = id_json["data"]["id"];
                    string hex_salt = id_json["data"]["salt"];
                    string hex_public_key = id_json["data"]["public_key"];

                    vector<unsigned char> salt_master = convert_salt(hex_salt);
                    vector<unsigned char> public_key = convert_public_key(hex_public_key);

                    SessionData session_data = save_session_token_load_master_key("session_token.data", new_token_id, salt_master, public_key);
                    cout << "You will added to server! Welcome!" << endl;

                    return session_data;
                }

            } else {
                throw runtime_error("Unknown answer");
            }
        } else {
            json current_token = {
                {"status", "current_id"},
                {"code", 200},
                {"data", {{"id", token.session_id}}}
            };

            vector<unsigned char> current_token_data = pack_data(current_token);

            send_package(current_token_data, cryption, session, socket);

            vector<unsigned char> id_response = recv_package(cryption, session, socket);
            json id_response_json = nlohmann::json::parse(id_response.begin(), id_response.end());

            if (id_response_json["status"] == "status_id" && id_response_json["code"] == 200) {
                cout << "You will added to server! Welcome!" << endl;

                return token;
            } else if (id_response_json["status"] == "status_id" && id_response_json["code"] == 300) {
                cout << "Your token hasn`t been finded!" << endl;
            }
            else {
                throw runtime_error("Invalid signature id_response");
            }
        }
    }
}

int main(int argc, char *argv[]) {

    QApplication app(argc, argv);

    if (sodium_init() < 0) {
        cerr << "Error init sodium! " << endl;
        return -1;

    MainWindow window;
    window.show();
        return app.exec();
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

        SessionData session_data = login(cryption, session, socket);

        ClientActivity activity(session, cryption, socket, session_data.password_hash, session_data.public_key, session_data.private_key);
        activity.main_thread();

    } catch (const system_error& e) {
        cout << "Client error: " << e.what() << endl;
    }
}