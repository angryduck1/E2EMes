#include "cryption.h"
#include <boost/asio.hpp>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>
#include "client_connection.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <mutex>

using namespace boost::asio;

using namespace std;

using ip::tcp;

using json = nlohmann::json;

#ifndef E2EMES_CLIENT_ACTIVITY_H
#define E2EMES_CLIENT_ACTIVITY_H

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
public:
    ClientActivity(Session& session, Cryption& cryption, tcp::socket& socket, vector<unsigned char>& password_hash, vector<unsigned char>& public_key, vector<unsigned char>& private_key);
    void update_activity();
    void update_sync_activity();
    bool time_out_activity();
    bool time_out_sync_activity();
    void main_thread();
    void input_thread();
    void init_new_chat(const string& name);
};


#endif //E2EMES_CLIENT_ACTIVITY_H
