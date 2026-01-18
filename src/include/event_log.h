#ifndef EVENT_LOG_H
#define EVENT_LOG_H

#include <tins/tins.h>
#include <vector>
#include <chrono>
#include <string>

using namespace std;
using namespace Tins;

enum class EventType {
    None = 0,
    SSH,
    FTP
};

enum class FTPEvent {
    None = 0,
    Login,
    Logout,
    WrongUser,
    WrongPassword
};

struct EventLog
{
  IPv4Address ip_addr;
  chrono::steady_clock::time_point event_time;
  EventType even_type = EventType::None;

  FTPEvent ftp_event = FTPEvent::None;
};

void clean_event_log(unordered_map<string, vector<EventLog>>& evenMap, chrono::seconds timeout) {
    auto now = chrono::steady_clock::now();

    for(auto it = evenMap.begin(); it != evenMap.end(); ) {
        vector<EventLog>& events = it->second;
        if(events.empty()){
            it = evenMap.erase(it);
            continue;
        }

        auto last_event_time = events.back().event_time;
        auto duration = now - last_event_time;
        auto elapsed = chrono::duration_cast<chrono::seconds>(duration);
        if(elapsed > timeout){
            it = evenMap.erase(it);
        } else {
            ++it;
        }
    }
}

#endif
