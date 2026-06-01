#ifndef E2EMES_CLIENT_CONNECTION_H
#define E2EMES_CLIENT_CONNECTION_H

#include <iostream>
#include <boost/asio.hpp>
#include "cryption.h"
#include <nlohmann/json.hpp>

using namespace std;
using namespace boost::asio;

using json = nlohmann::json;

using ip::tcp;

int send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket);

vector<unsigned char> recv_package(Cryption& cryption, Session& session, tcp::socket& socket);

vector<unsigned char> pack_data(json data_json);

#endif //E2EMES_CLIENT_CONNECTION_H
