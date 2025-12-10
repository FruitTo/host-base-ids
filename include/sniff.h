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
#include "./ip_port_connect.h"

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

const string BTMP_PATH = "/var/log/btmp";
const string VSFTPD_LOG_PATH = "/var/log/vsftpd.log";

inline void sniff(NetworkConfig &conf, const string &conninfo)
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
  unordered_map<string, IP_Port_Connect> ipPortMap;

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
    string key;
    uint16_t sport;
    uint16_t dport;
    string protocol = "";

    // TCP
    if (TCP* tcp = pdu->find_pdu<TCP>())
    {
       sport = tcp->sport();
       dport = tcp->dport();
       key = define_key(ip, sport, dport);
       protocol = tcp_define_protocol(conf, tcp);
    // UDP
    }
    else if(UDP* udp = pdu->find_pdu<UDP>())
    {
       sport = udp->sport();
       dport = udp->dport();
       key = define_key(ip, sport, dport);
    // ICMP
    }
    else if(ICMP* icmp = pdu->find_pdu<ICMP>())
    {
      sport = 0;
      dport = 0;
      return true;
    }

    // Flow
    auto it_flow = flowMap.find(key);
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

      flowMap[key] = flow;
    }
    else
    {
      // Create Flow
      Flow flow;
      flow.key = key;
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
      flowMap[key] = flow;
    }

    // EvenLog
    auto it_even = evenMap.find(client_ip);
    if(it_even == evenMap.end())
    {
      // Create Evenlog
      vector<EventLog> even_log;
      evenMap[client_ip] = even_log;
    }

    string ip_key = define_ip_key(ip, conf);

    // IP Port Connect
    auto it_ip = ipPortMap.find(ip_key);
    if(it_ip != ipPortMap.end())
    {
      // Update IP Port Map
      IP_Port_Connect& ip_port_connect = it_ip->second;
      ip_port_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      auto it = find(ip_port_connect.port_list.begin(), ip_port_connect.port_list.end(), port_connect);
      if(it == ip_port_connect.port_list.end())
      {
        ip_port_connect.port_list.push_back(port_connect);
      }
      auto duration = ip_port_connect.last_seen - ip_port_connect.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      if (ip_port_connect.port_list.size() > 80 && elapsed_seconds <= chrono::seconds(30))
      {
        if(ip_port_connect.port_scan == false)
        {
          cout << "[ALERT] PORT SCAN DETECTED " << endl;
          ip_port_connect.port_scan = true;
        }
      }

      clean_ip_port_connect(ipPortMap, IP_PORT_CONNECT_TIMEOUT);
    }
    else
    {
      // Create IP Port Map
      IP_Port_Connect ip_port_connect;
      ip_port_connect.ip = ip_key;
      ip_port_connect.first_seen = SystemClock::now();
      ip_port_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      ip_port_connect.port_list.push_back(port_connect);

      ipPortMap[ip_key] = ip_port_connect;
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
          cout << "[ALERT] SSH BRUTE FORCE DETECTED (High Rate): " << ssh.ip << endl;
        }
        else if (ssh.login_fail > 30)
        {
          cout << "[ALERT] SSH BRUTE FORCE DETECTED (Total Limit): " << ssh.ip << endl;
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
          cout << "[ALERT] FTP BRUTE FORCE DETECTED (High Rate): " << endl;
        }
        else if (ftp.login_fail > 30)
        {
          cout << "[ALERT] FTP BRUTE FORCE DETECTED (Total Limit): " << endl;
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

    clean_flow(flowMap, FLOW_TIMEOUT);
    clean_event_log(evenMap, IP_TIMEOUT);
    clean_ssh_state(sshMap, SSH_TIMEOUT);
    clean_ftp_state(ftpMap, FTP_TIMEOUT);
    return true;
  });
}

#endif