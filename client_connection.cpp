//
// Created by angryduck on 28.05.2026.
//

#include "client_connection.h"

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

vector<unsigned char> pack_data(json data_json) {
    string data_str = data_json.dump();

    vector<unsigned char> data(data_str.begin(), data_str.end());

    return data;
}

vector<unsigned char> convert_salt(const string& salt_hex) {
    vector<unsigned char> salt_master(crypto_pwhash_SALTBYTES);
    size_t bin_len;

    if (sodium_hex2bin(salt_master.data(), salt_master.size(), salt_hex.data(), salt_hex.size(), nullptr, &bin_len, nullptr) != 0) {
        throw runtime_error("Failed to convert master_salt");
    }

    return salt_master;
}

vector<unsigned char> convert_public_key(const string& public_key_hex) {
    vector<unsigned char> public_key(crypto_box_PUBLICKEYBYTES);
    size_t bin_len;

    if (sodium_hex2bin(public_key.data(), public_key.size(), public_key_hex.data(), public_key_hex.size(), nullptr, &bin_len, nullptr) != 0) {
        throw runtime_error("Failed to convert master_salt");
    }

    return public_key;
}

const string hex_to_string_convert_message(vector<unsigned char>& message) {
    string hex_salt(message.size() * 2, ' ');
    sodium_bin2hex(&hex_salt[0], hex_salt.size() + 1, message.data(), message.size());

    return hex_salt;
}

void generate_secret_initial(const string& file_name, vector<unsigned char>& password_hash, vector<unsigned char>& private_key, vector<unsigned char>& public_key_endpoint) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);

    vector<unsigned char> scalarmult_result(crypto_scalarmult_BYTES);

    if (crypto_scalarmult(scalarmult_result.data(), private_key.data(), public_key_endpoint.data()) != 0) {
        throw runtime_error("Failed to generate general secret!");
    }

    vector<unsigned char> shared_key(crypto_secretbox_KEYBYTES);
    crypto_generichash(shared_key.data(), shared_key.size(),
                       scalarmult_result.data(), scalarmult_result.size(), NULL, 0);

    vector<unsigned char> encrypted_private_key(shared_key.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(encrypted_private_key.data(), shared_key.data(), shared_key.size(), nonce, password_hash.data());

    ofstream file(file_name, ios::out | ios::binary);

    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(nonce), crypto_secretbox_NONCEBYTES);
        file.write(reinterpret_cast<const char*>(encrypted_private_key.data()), encrypted_private_key.size());
    } else {
        sodium_memzero(nonce, crypto_secretbox_NONCEBYTES);
        sodium_memzero(encrypted_private_key.data(), encrypted_private_key.size());

        throw runtime_error("Failed to save general secret!");
    }

    sodium_memzero(shared_key.data(), shared_key.size());
    sodium_memzero(scalarmult_result.data(), scalarmult_result.size());

    file.close();
}

vector<unsigned char> load_secret_initial(const string& file_name, vector<unsigned char>& password_hash) {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];

    vector<unsigned char> crypted_private_key(crypto_secretbox_KEYBYTES + crypto_secretbox_MACBYTES);

    ifstream file(file_name, ios::in | ios::binary);

    if (file.is_open()) {
        file.read(reinterpret_cast<char*>(nonce), crypto_secretbox_NONCEBYTES);
        file.read(reinterpret_cast<char*>(crypted_private_key.data()), crypted_private_key.size());
    } else {
        throw runtime_error("Failed to load general secret!");
    }

    vector<unsigned char> decrypted_private_key(crypto_secretbox_KEYBYTES);

    if (crypto_secretbox_open_easy(decrypted_private_key.data(), crypted_private_key.data(), crypted_private_key.size(), nonce, password_hash.data()) != 0) {
        throw runtime_error("Failed decrypt general key!");
    }

    return decrypted_private_key;
}

bool check_exist_gen_key(const string& file_name) {
    if (!filesystem::exists(file_name)) {
        return false;
    }

    uintmax_t  file_size = filesystem::file_size(file_name);

    unsigned sign_size = crypto_secretbox_KEYBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;

    if (file_size != sign_size) {
        cout << "Gen key file " << file_name << " is corrupted!" << endl;
        return false;
    }

    ifstream file(file_name, ios::in | ios::binary);

    if (!file.is_open()) {
        return false;
    }

    file.close();

    return true;
}
