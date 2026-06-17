#ifndef E2EMES_CLIENT_CONNECTION_H
#define E2EMES_CLIENT_CONNECTION_H

#include <iostream>
#include <boost/asio.hpp>
#include "../cryption.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>

using namespace std;
using namespace boost::asio;

using json = nlohmann::json;

using ip::tcp;

int send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket);

vector<unsigned char> recv_package(Cryption& cryption, Session& session, tcp::socket& socket);

vector<unsigned char> pack_data(json data_json);

vector<unsigned char> convert_salt(const string& salt_hex);

vector<unsigned char> convert_public_key(const string& public_key_hex);

const string hex_to_string_convert_message(vector<unsigned char>& message);

vector<unsigned char> convert_message(const string& message_hex);

void generate_secret_initial(const string& file_name, vector<unsigned char>& password_hash, vector<unsigned char>& private_key, vector<unsigned char>& public_key_endpoint);

vector<unsigned char> load_secret_initial(const string& file_name, vector<unsigned char>& password_hash);

vector<unsigned char> cryption_message(const string& message, vector<unsigned char>& nonce, vector<unsigned char>& general_key);

string decryption_message(vector<unsigned char>& message_hex, vector<unsigned char>& nonce_hex, vector<unsigned char>& general_key);

bool check_exist_gen_key(const string& name);

#endif //E2EMES_CLIENT_CONNECTION_H
