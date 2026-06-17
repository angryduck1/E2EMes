#include "../cryption.h"
#include <boost/asio.hpp>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>
#include "client_connection.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <sqlite_orm/sqlite_orm.h>
#include <cstdlib>

using namespace boost::asio;

using namespace std;

using ip::tcp;

using json = nlohmann::json;

using namespace sqlite_orm;

#ifndef E2EMES_CLIENT_ACTIVITY_H
#define E2EMES_CLIENT_ACTIVITY_H

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

class ClientActivity {
private:
    Session& session;
    Cryption& cryption;
    tcp::socket& socket;
    mutex mtx;

    vector<unsigned char>& password_hash;
    vector<unsigned char>& public_key;
    vector<unsigned char>& private_key;

    atomic<bool> newInput;
    atomic<bool> running;

    string input_text;

    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point last_sync_activity;

    mutex input_mutex;

    unordered_map<string, vector<unsigned char>> general_keys;

    any storage;

    string user_name;

    map<string, string> users_status;

    static auto create_storage(const string& file_name) {
        return make_storage(file_name, make_table("chats",
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
    ClientActivity(Session& session, Cryption& cryption, tcp::socket& socket, vector<unsigned char>& password_hash, vector<unsigned char>& public_key, vector<unsigned char>& private_key);
    ~ClientActivity();
    void update_activity();
    void update_sync_activity();
    bool time_out_activity();
    bool time_out_sync_activity();
    void main_thread();
    void input_thread();
    void init_new_chat(const string& name);
    void get_user_name();
    void send_new_message(const string& name);
    void sync_cloud();
    User get_last_message_from_bd(const string& name_init, const string& name_recp);
    void add_new_message_to_bd(const string& name_init, const string& name_recp, const string& message, const string& nonce, int& message_id, time_t& time);
    vector<User> get_chat_from_bd(const string &name_init, const string &name_recp);
    void init_bd(const string& file_name) {
        storage = create_storage(file_name);

        auto& db = get_storage();

        db.sync_schema();
    };
    void clear_screen();
};

#endif //E2EMES_CLIENT_ACTIVITY_H