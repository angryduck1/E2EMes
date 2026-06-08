#ifndef E2EMES_CONNECTIONS_H
#define E2EMES_CONNECTIONS_H

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "cryption.h"
#include <unordered_map>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>
#include <mutex>
#include <iostream>
#include <string>

using namespace std;
using namespace boost::asio;
using namespace sw::redis;

using json = nlohmann::json;

using ip::tcp;

class Connections {
private:
    struct SessionData {
        shared_ptr<tcp::socket> socket;
        Session session;
        std::chrono::steady_clock::time_point last_activity;

    };
    unordered_map<string, SessionData> sessionIds;

    std::mutex mtx;
public:
    Connections() = default;
    static int send_package(vector<unsigned char>& message, Cryption& cryption, Session& session, tcp::socket& socket);
    static vector<unsigned char> recv_package(Cryption& cryption, Session& session, tcp::socket& socket);
    void add_session(const string&, std::shared_ptr<tcp::socket>, Session& session);
    void client_thread(const string& session_id, Cryption& cryption, Session& session, shared_ptr<tcp::socket> socket, Redis& redis);
    void clean_disconnected(Redis& redis);
    void update_activity(const string& session_id);
    string get_chat_id(const string& session_id, Redis &redis);
    void new_chat(const string& session_id, const string& name, Redis &redis, Cryption &cryption, Session &session, shared_ptr<tcp::socket> socket);
    void sync_client(const string& session_id, Redis &redis, Cryption &cryption, Session &session, shared_ptr<tcp::socket> socket);
};


#endif //E2EMES_CONNECTIONS_H
