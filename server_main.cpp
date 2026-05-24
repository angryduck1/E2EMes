#include <iostream>
#include <sodium.h>
#include <boost/asio.hpp>
#include "cryption.h"
#include <thread>
#include <fstream>
#include <nlohmann/json.hpp>
#include "connections.h"

using namespace std;
using namespace boost::asio;

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

void login(shared_ptr<tcp::socket> socket, Cryption& cryption, Connections& connections) {
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
        string new_token_id = generate_session_token();

        connections.add_session(new_token_id, socket, session);

        json new_token_id_json = {
            {"status", "new_id"},
            {"code", 200},
            {"data", { {"id", new_token_id} }}
        };

        vector<unsigned char> new_token_id_json_send = pack_data(new_token_id_json);
        connections.send_package(new_token_id_json_send, cryption, session, *socket);
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
               login(sock_ptr, cryption, connections);
            });

            new_session_thread.detach();
        } catch (const system_error& e) {
            cout << "Server error: " << e.what() << endl;
        }
    }

    return 0;
}