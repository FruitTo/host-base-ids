#ifndef SNIFF_H
#define SNIFF_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <iostream>
#include <ctime>
#include <unordered_set>

#include <pqxx/pqxx>
#include <tins/tins.h>
#include <tins/tcp.h>

#include "./interface.h"
#include "./date.h"
#include "./network_config.h"
#include "./write_json.h"
#include "./flow.h"
#include "./define_protocol.h"
#include "./define_key.h"
#include "./event_log.h"
#include "./ssh_state.h"
#include "./ftp_state.h"
#include "./ip_connect.h"
#include "./udp_connect.h"

using namespace Tins;
using namespace std;
using namespace chrono;

using Tins::TCP;
using Clock = chrono::steady_clock;
using SystemClock = chrono::system_clock;

const chrono::seconds FLOW_TIMEOUT = chrono::seconds(10);
const chrono::seconds IP_TIMEOUT = chrono::seconds(10);
const chrono::seconds SSH_TIMEOUT = chrono::seconds(30);
const chrono::seconds FTP_TIMEOUT = chrono::seconds(30);
const chrono::seconds IP_PORT_CONNECT_TIMEOUT = chrono::seconds(30);
const chrono::seconds UDP_PORT_CONNECT_TIMEOUT = chrono::seconds(30);

const string BTMP_PATH = "/var/log/btmp";
const string VSFTPD_LOG_PATH = "/var/log/vsftpd.log";


inline void sniff(NetworkConfig &conf, const string &conninfo, bool mode)
{
  pqxx::connection conn{conninfo};

  // Initial Log Variable
  string currentDay = currentDate();
  string currentTime = timeStamp();
  string currentPath = "./logs/" + getPath();
  filesystem::create_directories(currentPath);
  auto writer = make_unique<PacketWriter>(currentPath + conf.NAME + "_" + currentDay + "_" + currentTime + ".pcap", DataLinkType<EthernetII>());

  // Map
  unordered_map<string, Flow> flowMap;
  unordered_map<string, vector<EventLog>> evenMap;
  unordered_map<string, SSH_State> sshMap;
  unordered_map<string, FTP_State> ftpMap;
  unordered_map<string, IP_Connect> ipConnectMap;
  unordered_map<string, UDP_Connect> udpConnectMap;

  // Port List
  std::unordered_set<uint16_t> portList;

  auto merge_ports = [&](const std::vector<uint16_t>& source_ports) {
    portList.insert(source_ports.begin(), source_ports.end());
  };

  if(conf.HTTP_SERVERS) merge_ports(conf.HTTP_PORTS);
  if(conf.SSH_SERVERS) merge_ports(conf.SSH_PORTS);
  if(conf.FTP_SERVERS) merge_ports(conf.FTP_PORTS);
  if(conf.TELNET_SERVERS) merge_ports(conf.TELNET_PORTS);
  if(conf.SIP_SERVERS) merge_ports(conf.SIP_PORTS);

  // Sniffer
  SnifferConfiguration cfg;
  cfg.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, cfg);
  sniffer.sniff_loop([&](Packet &pkt)
  {
    PDU* pdu = pkt.pdu();
    if (!pdu) return true;
    IP &ip = pdu->rfind_pdu<IP>();

    // Write Pcap Log
    string date = currentDate();
    string path = getPath();
    if (currentDay != date)
    {
      currentDay  = date;
      currentPath = path;
      filesystem::create_directories(currentPath);
      string ts = timeStamp();
      writer = make_unique<PacketWriter>
      (
        currentPath + conf.NAME + "_" + currentDay + "_" + ts + ".pcap", DataLinkType<EthernetII>()
      );
    }
    writer->write(pkt);

    string client_ip = (ip.src_addr() != conf.IP) ? ip.src_addr().to_string() : ip.dst_addr().to_string();

    // Defined Flow Key (src_addr + src_port + dst_addr + dst_port + tcp | udp | icmp)
    string flow_key;
    uint16_t sport;
    uint16_t dport;
    string protocol = "";

    // TCP
    if (TCP* tcp = pdu->find_pdu<TCP>())
    {
       sport = tcp->sport();
       dport = tcp->dport();
       flow_key = define_key(ip, sport, dport);
       protocol = tcp_define_protocol(conf, tcp);
    }
    // UDP
    else if(UDP* udp = pdu->find_pdu<UDP>())
    {
       sport = udp->sport();
       dport = udp->dport();
       flow_key = define_key(ip, sport, dport);
    }
    // ICMP
    else if(ICMP* icmp = pdu->find_pdu<ICMP>())
    {
      sport = 0;
      dport = 0;
      return true;
    }

    // Flow
    auto it_flow = flowMap.find(flow_key);
    if(it_flow != flowMap.end())
    {
      // Update Flow
      Flow& flow = it_flow->second;
      flow.count++;
      flow.last_seen = Clock::now();

      // Establish
      if(TCP* tcp = pdu->find_pdu<TCP>())
      {
        if(flow.count == 2 && flow.sync == true)
        {
          if(tcp->flags() == (TCP::SYN | TCP::ACK))
          {
            flow.sync_ack = true;
          }
        }
        else if(flow.count == 3 && flow.sync_ack == true)
        {
          if(tcp->flags() == TCP::ACK)
          {
            flow.ack = true;
            if(flow.sync && flow.sync_ack && flow.ack)
            {
              flow.established = true;
            }
          }
        }
      }

      flowMap[flow_key] = flow;
    }
    else
    {
      // Create Flow
      Flow flow;
      flow.key = flow_key;
      flow.src_addr = ip.src_addr();
      flow.sport = sport;
      flow.dst_addr = ip.dst_addr();
      flow.dport = dport;
      flow.proto = protocol;

      flow.create_at = Clock::now();
      flow.last_seen = Clock::now();

      if (TCP* tcp = pdu->find_pdu<TCP>())
      {
        if(tcp->flags() == 0)
        {
          cout << "[ALERT] TCP NULL SCAN DETECTED" << endl;
        }
        else if(tcp->flags() == TCP::SYN)
        {
          flow.sync = true;
        }
      }
      else if(UDP* udp = pdu->find_pdu<UDP>())
      {

      }

      flow.count++;
      flowMap[flow_key] = flow;
    }

    string ip_key = define_ip_key(ip, conf);

    // IP Connect
    auto it_ip = ipConnectMap.find(ip_key);
    if(it_ip != ipConnectMap.end())
    {
      // Update IP Connect Map
      IP_Connect& ip_connect = it_ip->second;

      ip_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      auto it = find(ip_connect.port_list.begin(), ip_connect.port_list.end(), port_connect);
      if(it == ip_connect.port_list.end())
      {
        ip_connect.port_list.push_back(port_connect);
      }
      else
      {
        if (TCP* tcp = pdu->find_pdu<TCP>())
        {
          if (tcp->flags() == TCP::SYN && portList.count(tcp->dport()))
         {
            ip_connect.syn_count++;
         }
        }
      }

      auto duration = ip_connect.last_seen - ip_connect.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      if (ip_connect.port_list.size() > 80 && elapsed_seconds <= chrono::seconds(30))
      {
        if(ip_connect.port_scan == false)
        {
          cout << "[ALERT] PORT SCAN DETECTED " << endl;
          ip_connect.port_scan = true;
        }
      }

      if (ip_connect.syn_count > 80 && elapsed_seconds <= chrono::seconds(30))
      {
        if(ip_connect.syn_flood == false)
        {
          cout << "[ALERT] SYN FLOOD DETECT (IP : "<< ip_connect.ip << " )" << endl;
          ip_connect.syn_flood = true;
        }

        // IPS
        if(ip_connect.blocked == false){
          if(mode && ip_connect.syn_flood)
          {
            string block_command = "sudo iptables -A INPUT -s " + ip_connect.ip + " -j DROP";
            if (system(block_command.c_str()) == 0)
            {
              cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ip_connect.ip << endl;
            }
            else
            {
              cerr << "[ACTION FAILED] COULD NOT EXECUTE IPTABLES COMMAND." << endl;
            }
          }
          ip_connect.blocked = true;
        }
      }

    }
    else
    {
      // Create IP Connect Map
      IP_Connect ip_connect;
      ip_connect.ip = ip_key;
      ip_connect.flow_key = flow_key;
      ip_connect.first_seen = SystemClock::now();
      ip_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      ip_connect.port_list.push_back(port_connect);

      if (TCP* tcp = pdu->find_pdu<TCP>())
      {
        if (tcp->flags() == TCP::SYN && portList.count(tcp->dport()))
        {
          ip_connect.syn_count++;
        }
      }
      ipConnectMap[ip_key] = ip_connect;
    }

    // UDP Connect
    if(UDP* udp = pdu->find_pdu<UDP>())
    {
      auto it_ip = ipConnectMap.find(ip_key);
      if(it_ip != ipConnectMap.end());

      auto it_udp = udpConnectMap.find(ip_key);
      if(it_udp != udpConnectMap.end())
      {
        // Update UDP Map
        UDP_Connect& udp_connect = it_udp->second;

        udp_connect.packet_count++;
        udp_connect.last_seen = SystemClock::now();

        uint16_t port_connect = define_port_connect(pdu, ip_key);
        auto it = find(udp_connect.port_list.begin(), udp_connect.port_list.end(), port_connect);
        if(it == udp_connect.port_list.end())
        {
          udp_connect.port_list.push_back(port_connect);
        }

        if (!portList.count(udp->dport())){
          udp_connect.unreach_count++;
        }

        if(udp_connect.unreach_count > 30 && udp_connect.udp_flood == false){
          cout << "[ALERT] UDP Flood DETECTED" << endl;
          udp_connect.udp_flood = true;
        }
      }
      else
      {
        // Create UDP Map
        UDP_Connect udp_connect;
        udp_connect.ip = ip_key;
        udp_connect.flow_key = flow_key;
        udp_connect.first_seen = SystemClock::now();
        udp_connect.last_seen = SystemClock::now();
        udp_connect.packet_count = 1;

        uint16_t port_connect = define_port_connect(pdu, ip_key);
        udp_connect.port_list.push_back(port_connect);

        if (!portList.count(udp->dport())){
          udp_connect.unreach_count++;
        }

        udpConnectMap[ip_key] = udp_connect;
      }
    }

    // IF SSH
    if (protocol == "ssh")
    {
      auto it_ssh = sshMap.find(ip_key);
      if (it_ssh != sshMap.end())
      {
        // Update SSH State
        SSH_State& ssh = it_ssh->second;
        ssh.last_seen = SystemClock::now();
        auto duration = ssh.last_seen - ssh.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        ssh_read_fail_state(BTMP_PATH, ssh);
        if (elapsed_seconds < chrono::seconds(60) && ssh.login_fail > 10)
        {
          if(ssh.ssh_brute_force == false)
          {
            cout << "[ALERT] SSH BRUTE FORCE DETECTED (High Rate): " << ssh.ip << endl;
            ssh.ssh_brute_force = true;
          }

          // IPS
          if(ssh.blocked == false){
            if(mode && ssh.ssh_brute_force)
            {
              string block_command = "sudo iptables -A INPUT -s " + ssh.ip + " -j DROP";
              if (system(block_command.c_str()) == 0)
              {
                cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ssh.ip << endl;
              }
              else
              {
                cerr << "[ACTION FAILED] COULD NOT EXECUTE IPTABLES COMMAND." << endl;
              }
              ssh.blocked = true;
            }
          }
        }
        else if (ssh.login_fail > 100)
        {
          if(ssh.ssh_brute_force == false)
          {
            cout << "[ALERT] SSH BRUTE FORCE DETECTED (Total Limit): " << ssh.ip << endl;
            ssh.ssh_brute_force = true;
          }

          // IPS
          if(ssh.blocked == false){
            if(mode && ssh.ssh_brute_force)
            {
              string block_command = "sudo iptables -A INPUT -s " + ssh.ip + " -j DROP";
              if (system(block_command.c_str()) == 0)
              {
                cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ssh.ip << endl;
              }
              else
              {
                cerr << "[ACTION FAILED] COULD NOT EXECUTE IPTABLES COMMAND." << endl;
              }
              ssh.blocked = true;
            }
          }
        }
      }
      else
      {
        // Create SSH State
        SSH_State ssh;
        ssh.ip = ip.src_addr().to_string();
        ssh.first_seen = SystemClock::now();
        ssh.last_seen = SystemClock::now();
        ssh.login_fail = 0;

        sshMap[ip_key] = ssh;
      }
    }

    // IF FTP
    if (protocol == "ftp")
    {
      auto it_ftp = ftpMap.find(ip_key);
      if (it_ftp != ftpMap.end())
      {
        // Update FTP State
        FTP_State& ftp = it_ftp->second;
        ftp.last_seen = SystemClock::now();
        auto duration = ftp.last_seen - ftp.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        ftp_read_fail_state(VSFTPD_LOG_PATH, ftp);
        if (elapsed_seconds < chrono::seconds(60) && ftp.login_fail > 10)
        {
          if(ftp.ftp_brute_force == false)
          {
            cout << "[ALERT] FTP BRUTE FORCE DETECTED (High Rate): " << endl;
            ftp.ftp_brute_force = true;
          }

          // IPS
          if(ftp.blocked == false)
          {
            if(mode && ftp.ftp_brute_force)
            {
              string block_command = "sudo iptables -A INPUT -s " + ftp.ip + " -j DROP";
              if (system(block_command.c_str()) == 0)
              {
                cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ftp.ip << endl;
              }
              else
              {
                cerr << "[ACTION FAILED] COULD NOT EXECUTE IPTABLES COMMAND." << endl;
              }
            }
            ftp.blocked = true;
          }
        }
        else if (ftp.login_fail > 100)
        {
          if(ftp.ftp_brute_force == false)
          {
            cout << "[ALERT] FTP BRUTE FORCE DETECTED (Total Limit): " << endl;
            ftp.ftp_brute_force = true;
          }

          // IPS
          if(ftp.blocked == false)
          {
            if(mode && ftp.ftp_brute_force)
            {
              string block_command = "sudo iptables -A INPUT -s " + ftp.ip + " -j DROP";
              if (system(block_command.c_str()) == 0)
              {
                cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ftp.ip << endl;
              }
              else
              {
                cerr << "[ACTION FAILED] COULD NOT EXECUTE IPTABLES COMMAND." << endl;
              }
            }
            ftp.blocked = true;
          }
        }
      }
      else
      {
        // Create FTP State
        FTP_State ftp;
        ftp.ip = ip.src_addr().to_string();
        ftp.first_seen = SystemClock::now();
        ftp.last_seen = SystemClock::now();
        ftp.login_fail = 0;

        ftpMap[ip_key] = ftp;
      }
    }

    // EvenLog
    auto it_even = evenMap.find(client_ip);
    if(it_even == evenMap.end())
    {
      // Create Evenlog
      vector<EventLog> even_log;
      evenMap[client_ip] = even_log;
    }

    clean_flow(flowMap, FLOW_TIMEOUT);
    clean_event_log(evenMap, IP_TIMEOUT);
    clean_ssh_state(sshMap, SSH_TIMEOUT);
    clean_ftp_state(ftpMap, FTP_TIMEOUT);
    clean_ip_connect(ipConnectMap, IP_PORT_CONNECT_TIMEOUT);
    clean_udp_connect(udpConnectMap, UDP_PORT_CONNECT_TIMEOUT);
    return true;
  });
}

#endif