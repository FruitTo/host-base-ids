#include "./include/BS_thread_pool.hpp"
#include "./include/interface.h"
#include "./include/sniff.h"
#include "./include/db_connect.h"
#include "./include/network_config.h"

#include <pqxx/pqxx>
#include <iostream>
#include <optional>
#include <limits>
#include <string>
#include <vector>
#include <future>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>

using namespace std;
using namespace BS;

inline void parsePorts(const string &input, vector<string> &target)
{
  istringstream iss(input);
  string port;
  while (iss >> port) target.push_back(port);
}

int main()
{
  // string conninfo = db_connect();
  // if(conninfo == "")return 1;

  string conninfo = "user=postgres password=postgres host=localhost port=5432 dbname=postgres target_session_attrs=read-write";

  vector<string> interfaceName = getInterfaceName();
  vector<NetworkConfig> configuredInterfaces;
  thread_pool pool(interfaceName.size());
  vector<future<void>> task;

  // Select Mode.
  bool mode;
  char modeInput;
  cout << "IPS Mode ? [y/n]: ";
  cin >> modeInput;
  cout << endl;
  mode = (modeInput == 'y' || modeInput == 'Y');

  // Config Interface
  for (const string &iface : interfaceName)
  {
    NetworkConfig conf;
    char yesno;
    string input;

    conf.NAME = iface;
    conf.IP = getIpInterface(iface);
    conf.HOME_NET = getIpInterface(iface);
    conf.EXTERNAL_NET = "!" + *conf.HOME_NET;

    cout << "\nConfiguring services for interface: " << iface << "\n";

    auto askService = [&](const string &name, optional<bool> &flag, vector<string> &ports)
    {
      cout << name << " Service? [y/n]: ";
      cin >> yesno;
      cin.ignore(numeric_limits<streamsize>::max(), '\n');
      bool enabled = (yesno == 'y' || yesno == 'Y');
      flag = enabled;
      if (enabled)
      {
        cout << "Enter " << name << " port(s) (space separated): ";
        getline(cin, input);
        parsePorts(input, ports);
      }
    };

    askService("HTTP",   conf.HTTP_SERVERS,   conf.HTTP_PORTS);
    askService("SSH",    conf.SSH_SERVERS,    conf.SSH_PORTS);
    askService("FTP",    conf.FTP_SERVERS,    conf.FTP_PORTS);
    askService("Oracle", conf.SQL_SERVERS,    conf.ORACLE_PORTS);
    askService("TELNET", conf.TELNET_SERVERS, conf.FILE_DATA_PORTS);

    configuredInterfaces.push_back(conf);
  }

  // Sniffer
  for (NetworkConfig &conf : configuredInterfaces)
  {
    task.push_back(pool.submit_task([conf, conninfo]() mutable {
      try {
        sniff(conf, conninfo);
      } catch (const std::exception& e) {
        cout << std::string("sniff exception: ") + e.what();
      }
    }));
  }

  for (auto &t : task) t.wait();

  return 0;
}
