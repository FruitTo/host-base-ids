#ifndef DEVICE_H
#define DEVICE_H

#include "packet.h"
#include <vector>
#include <string>
#include <optional>

std::vector<NetworkConfig> getDevices()
{
    std::vector<NetworkConfig> devices;

    auto addDevice = [&](const std::string &name, const std::string &ip,
                         std::vector<std::string> http_ports = {},
                         std::vector<std::string> ssh_ports = {},
                         std::vector<std::string> ftp_ports = {},
                         std::vector<std::string> sip_ports = {},
                         bool http_srv = false,
                         bool ssh_srv = false,
                         bool ftp_srv = false,
                         bool sip_srv = false)
    {
        NetworkConfig cfg{};
        cfg.NAME = name;
        cfg.IP = ip;
        cfg.HOME_NET = "192.168.10.0/24";
        cfg.EXTERNAL_NET = "any";
        cfg.HTTP_PORTS = http_ports;
        cfg.SSH_PORTS = ssh_ports;
        cfg.FTP_PORTS = ftp_ports;
        cfg.SIP_PORTS = sip_ports;
        cfg.HTTP_SERVERS = http_srv;
        cfg.SSH_SERVERS = ssh_srv;
        cfg.FTP_SERVERS = ftp_srv;
        cfg.SIP_SERVERS = sip_srv;
        devices.push_back(cfg);
    };

    addDevice("WinServer2016_DC_DNS", "192.168.10.3",
              {}, {"22"}, {"21"}, {}, false, true, true);
    addDevice("Ubuntu16_WebServer", "192.168.10.50",
              {"80", "443"}, {"22"}, {"21"}, {}, true, true, true);
    addDevice("Ubuntu12", "192.168.10.51",
              {"80", "443"}, {"22"}, {"21"}, {}, true, true, true);
    addDevice("Ubuntu14_32bit", "192.168.10.19",
              {"80", "443"}, {"22"}, {"21"});
    addDevice("Ubuntu14_64bit", "192.168.10.17",
              {"80", "443"}, {"22"}, {"21"});
    addDevice("Ubuntu16_32bit", "192.168.10.16",
              {"80", "443"}, {"22"}, {"21"});
    addDevice("Ubuntu16_64bit", "192.168.10.12",
              {"80", "443"}, {"22"}, {"21"});

    addDevice("Win7Pro_64bit", "192.168.10.9", {"80", "443"});
    addDevice("Win8_1_64bit", "192.168.10.5", {"80", "443"});
    addDevice("WinVista_64bit", "192.168.10.8", {"80", "443"});
    addDevice("Win10_pro_32bit", "192.168.10.14", {"80", "443"});
    addDevice("Win10_pro_64bit", "192.168.10.15", {"80", "443"});

    addDevice("Mac_OSX", "192.168.10.25", {"80", "443"});

    return devices;
}

#endif
