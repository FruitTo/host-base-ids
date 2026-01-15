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
#include <future>
#include <unistd.h>
#include <sys/types.h>
#include <cstring>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cstdint>

using namespace std;
using namespace BS;

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>

inline void parsePorts(const std::string &input, std::vector<uint16_t> &target)
{
  std::istringstream iss(input);
  std::string port_str;

  while (iss >> port_str)
  {
    try
    {
      int port_int = std::stoi(port_str);

      if (port_int > 0 && port_int <= 65535)
      {
        target.push_back(static_cast<uint16_t>(port_int));
      }
      else
      {
        std::cerr << "Warning: Port number " << port_str << " is out of valid range (1-65535) and was skipped." << std::endl;
      }
    }
    catch (const std::invalid_argument& e)
    {
      std::cerr << "Warning: Invalid port format '" << port_str << "' found and was skipped." << std::endl;
    }
    catch (const std::out_of_range& e)
    {
      std::cerr << "Warning: Port number " << port_str << " is too large and was skipped." << std::endl;
    }
  }
}

int main()
{
  // string conninfo = db_connect();
  // if(conninfo == "")return 1;

  string conninfo = "user=postgres password=postgres host=localhost port=5432 dbname=alert_attack target_session_attrs=read-write";

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

    auto askService = [&](const string &name, optional<bool> &flag, vector<uint16_t> &ports)
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

    configuredInterfaces.push_back(conf);
  }

  // Sniffer
  for (NetworkConfig &conf : configuredInterfaces)
  {
    task.push_back(pool.submit_task([conf, conninfo, mode]() mutable {
      try {
        sniff(conf, conninfo, mode);
      } catch (const exception& e) {
        cout << string("sniff exception: ") + e.what();
      }
    }));
  }

  for (auto &t : task) t.wait();

  return 0;
}
