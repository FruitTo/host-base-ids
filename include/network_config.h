#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct NetworkConfig {
   std::string NAME;
   std::string IP;

   std::optional<std::string> HOME_NET;
   std::optional<std::string> EXTERNAL_NET;

   std::vector<std::string> HTTP_PORTS;
   std::vector<std::string> SSH_PORTS;
   std::vector<std::string> FTP_PORTS;
   std::vector<std::string> SIP_PORTS;

   std::vector<std::string> ORACLE_PORTS;
   std::vector<std::string> FILE_DATA_PORTS;

   std::optional<bool> HTTP_SERVERS = false;
   std::optional<bool> SSH_SERVERS = false;
   std::optional<bool> FTP_SERVERS = false;

   std::optional<bool> TELNET_SERVERS = false;
   std::optional<bool> SMTP_SERVERS = false;
   std::optional<bool> SIP_SERVERS = false;
   std::optional<bool> SQL_SERVERS = false;
};

#endif