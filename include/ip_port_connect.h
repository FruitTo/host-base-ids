#ifndef IP_PORT_CONNECT_H
#define IP_PORT_CONNECT_H

#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

struct IP_Port_Connect
{
  string ip;
  chrono::system_clock::time_point first_seen;
  chrono::system_clock::time_point last_seen;
  vector<uint16_t> port_list;
  bool port_scan = false;
};

void clean_ip_port_connect(unordered_map<string, IP_Port_Connect> ipPortMap, chrono::seconds timeout) {
    auto now = chrono::system_clock::now();

    for (auto it = ipPortMap.begin(); it != ipPortMap.end();)
    {
        IP_Port_Connect &ip_port_conect = it->second;
        auto duration = now - ip_port_conect.last_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);

        if (elapsed_seconds > timeout) {
            it = ipPortMap.erase(it);
        } else {
            ++it;
        }
    }

}

#endif