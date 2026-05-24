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

string generate_session_token(const string& filename) {
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

    ofstream file(filename);
    if (!file) {
        throw runtime_error("Error opening file to save session");
    }

    file << b64_buffer;

    file.close();

    return b64_buffer;
}

string load_session_token(const string& file_name) {
    ifstream file(file_name);

    if (file.is_open()) {
        stringstream buffer;
        buffer << file.rdbuf();
        string content = buffer.str();

        return content;
    }

    return "";
}

void save_session_token(const string& file_name, string token_id) {
    ofstream file(file_name);

    if (file.is_open()) {
        file << token_id;
    } else {
        throw runtime_error("Failed to save session token!");
    }

    file.close();
}

void login(Cryption& cryption, Session& session, tcp::socket& socket) {
    vector<unsigned char> get_log = recv_package(cryption, session, socket);

    json log = nlohmann::json::parse(get_log.begin(), get_log.end());

    if (log["status"] == "get_id" && log["code"] == 100) {
        string token = load_session_token("session_token.data");
        if (token == "") {
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
                cout << id_json.dump() << endl;
                string new_token_id = id_json["data"]["id"].get<string>();
                save_session_token("session_token.data", new_token_id);
            } else {
                throw runtime_error("Invalid signature new_id code 200");
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