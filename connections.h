#ifndef E2EMES_CONNECTIONS_H
#define E2EMES_CONNECTIONS_H

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "cryption.h"
#include <unordered_map>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

using namespace std;
using namespace boost::asio;

using json = nlohmann::json;

using ip::tcp;

class Connections {
private:
    unordered_map<string, pair<shared_ptr<tcp::socket>, Session>> sessionIds;
public:
    Connections() = default;
    static int send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket);
    static vector<unsigned char> recv_package(Cryption& cryption, Session& session, tcp::socket& socket);
    void add_session(string session_id, std::shared_ptr<tcp::socket>, Session& session);
};


#endif //E2EMES_CONNECTIONS_H
