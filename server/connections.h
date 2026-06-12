#ifndef E2EMES_CONNECTIONS_H
#define E2EMES_CONNECTIONS_H

#include <nlohmann/json.hpp>
#include <boost/asio.hpp>
#include "../cryption.h"
#include <unordered_map>
#include <iostream>
#include <nlohmann/json.hpp>
#include <sw/redis++/redis++.h>
#include <mutex>
#include <iostream>
#include <string>
#include <sqlite_orm/sqlite_orm.h>
#include <ctime>
#include <any>

using namespace std;
using namespace boost::asio;
using namespace sw::redis;
using namespace sqlite_orm;

using json = nlohmann::json;

using ip::tcp;

struct User {
    int id;
    int message_id;
    time_t message_time;
    string sender_name;
    string recp_name;
    string message;
    string nonce;

    auto operator<=>(const User &) const=default;
};

class Connections {
private:
    struct SessionData {
        shared_ptr<tcp::socket> socket;
        Session session;
        std::chrono::steady_clock::time_point last_activity;
    };

    unordered_map<string, SessionData> sessionIds;

    std::mutex mtx;

    any storage;

    static auto create_storage(const string& file_name) {
        return make_storage(file_name, make_table("users",
                make_column("id", &User::id, primary_key().autoincrement()),
                make_column("message_id", &User::message_id),
                make_column("message_time", &User::message_time),
                make_column("sender_name", &User::sender_name),
                make_column("recp_name", &User::recp_name),
                make_column("message", &User::message),
                make_column("nonce", &User::nonce)
        ));
    }

    auto& get_storage() {
        return *any_cast<decltype(create_storage(""))>(&storage);
    }

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
    void new_message(const string& session_id, const string& name, Redis &redis, Cryption &cryption, Session &session, shared_ptr<tcp::socket> socket);
    User add_new_message_to_bd(const string& name_init, const string& name_recp, const string& message, const string& nonce);
    User get_last_message_from_bd(const string& name_init, const string& name_recp);
    vector<User> get_last_messages_from_bd(const string& name_init, const string& name_recp, int& last_message_id);
    vector<unsigned char> pack_data(json data_jsonW);

    void init_bd(const string& file_name) {
        storage = create_storage(file_name);

        auto& db = get_storage();

        db.sync_schema();
    };
};


#endif //E2EMES_CONNECTIONS_H
