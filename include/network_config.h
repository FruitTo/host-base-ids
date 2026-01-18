#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct NetworkConfig
{
   std::string NAME;
   std::string IP;

   std::optional<std::string> HOME_NET;
   std::optional<std::string> EXTERNAL_NET;

   std::vector<std::uint16_t> HTTP_PORTS;
   std::vector<std::uint16_t> SSH_PORTS;
   std::vector<std::uint16_t> FTP_PORTS;
   std::vector<std::uint16_t> SIP_PORTS;
   std::vector<std::uint16_t> TELNET_PORTS;

   std::vector<std::uint16_t> ORACLE_PORTS;
   std::vector<std::uint16_t> FILE_DATA_PORTS;

   std::optional<bool> HTTP_SERVERS = false;
   std::optional<bool> SSH_SERVERS = false;
   std::optional<bool> FTP_SERVERS = false;

   std::optional<bool> TELNET_SERVERS = false;
   std::optional<bool> SMTP_SERVERS = false;
   std::optional<bool> SIP_SERVERS = false;
   std::optional<bool> SQL_SERVERS = false;
};

void block_ip(const std::string &ip_address, std::chrono::minutes minutes)
{
   if (ip_address.empty()) return;

   std::string block_cmd = "sudo iptables -I INPUT -s " + ip_address + " -j DROP";
   std::string unblock_cmd = "sudo iptables -D INPUT -s " + ip_address + " -j DROP";
   std::string schedule_cmd = "echo \"" + unblock_cmd + "\" | at now + " + std::to_string(minutes.count()) + " minutes";
   std::cout << "[ACTION] Block IP: " << ip_address << " for " << minutes.count() << " minutes." << std::endl;
   int block_result = std::system(block_cmd.c_str());

   if (block_result == 0)
   {
      std::cout << "[SUCCESS] IP " << ip_address << " is now filtered." << std::endl;
      int schedule_result = std::system(schedule_cmd.c_str());
      if (schedule_result != 0)
      {
         std::cerr << "[WARNING] 'at' command failed. Please install with: sudo apt install at" << std::endl;
      }
   }
   else
   {
      std::cerr << "[ERROR] Failed to execute iptables. Check sudo permissions." << std::endl;
   }
}
#endif