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
#include <tins/tcp_ip/stream_follower.h>

#include "./interface.h"
#include "./date.h"
#include "./network_config.h"
#include "./write_json.h"
#include "./define_protocol.h"
#include "./define_key.h"
#include "./event_log.h"
#include "./ssh_state.h"
#include "./ftp_state.h"
#include "./http_state.h"
#include "./ip_connect.h"
#include "./udp_connect.h"
#include "./icmp_connect.h"
#include "./tcp_stream_callback.h"

using namespace std;

using namespace Tins;
using Tins::TCP;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

using namespace chrono;
using Clock = chrono::steady_clock;
using SystemClock = chrono::system_clock;

// ********************************* MUST CONFIG BEFORE USING *********************************
// Timeout
const chrono::seconds IP_TIMEOUT = chrono::seconds(10);
const chrono::seconds SSH_TIMEOUT = chrono::seconds(30);
const chrono::seconds FTP_TIMEOUT = chrono::seconds(30);
const chrono::seconds HTTP_TIMEOUT = chrono::seconds(30);
const chrono::seconds IP_PORT_CONNECT_TIMEOUT = chrono::seconds(30);
const chrono::seconds UDP_PORT_CONNECT_TIMEOUT = chrono::seconds(30);
const chrono::seconds ICMP_CONNECT_TIMEOUT = chrono::seconds(30);

// LIMIT
const double ICMP_PPS_LIMIT = 100.0;
const int PORT_CONNECT_LIMIT = 80;
const chrono::seconds PORT_CONNECT_DURATION_LIMIT = chrono::seconds(30);
const int SYN_CONNECT_LIMIT = 10000;
const chrono::seconds SYN_CONNECT_DURATION_LIMIT = chrono::seconds(30);
const int UNREACH_COUNT_LIMIT = 30;
const int UDP_PPS_LIMIT = 10000;
const int SSH_LOGIN_FAIL_LIMIT = 10;
const int SSH_LOGIN_FAIL_DURATION_LIMIT = 100;
const chrono::seconds SSH_DURATION_LIMIT = chrono::seconds(60);
const int FTP_LOGIN_FAIL_LIMIT = 10;
const int FTP_LOGIN_FAIL_DURATION_LIMIT = 100;
const chrono::seconds FTP_DURATION_LIMIT = chrono::seconds(60);

// Path
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
  unordered_map<string, vector<EventLog>> evenMap;
  unordered_map<string, SSH_State> sshMap;
  unordered_map<string, FTP_State> ftpMap;
  unordered_map<string, HTTP_State> httpMap;
  unordered_map<string, IP_Connect> ipConnectMap;
  unordered_map<string, UDP_Connect> udpConnectMap;
  unordered_map<string, ICMP_Connect> icmpConnectMap;

  // Port List
  unordered_set<uint16_t> portList;

  auto merge_ports = [&](const vector<uint16_t> &source_ports)
  {
    portList.insert(source_ports.begin(), source_ports.end());
  };

  if (conf.HTTP_SERVERS)
    merge_ports(conf.HTTP_PORTS);
  if (conf.SSH_SERVERS)
    merge_ports(conf.SSH_PORTS);
  if (conf.FTP_SERVERS)
    merge_ports(conf.FTP_PORTS);

  // Stream Manager
  StreamFollower follower;
  // Callbacks for new streams
  follower.new_stream_callback([&](Stream &stream)
  {
    stream.client_data_callback([&](Stream &s)
    {
      on_client_data(s, httpMap);
    });

    stream.server_data_callback([&](Stream &s)
    {
      on_server_data(s, httpMap);
    });

    stream.auto_cleanup_payloads(true);
    stream.auto_cleanup_client_data(true);
    stream.auto_cleanup_server_data(true);
  });
  // Callbacks for terminated streams
  follower.stream_termination_callback([&](Stream &stream, StreamFollower::TerminationReason reason) {});

  // Sniffer
  SnifferConfiguration cfg;
  cfg.set_promisc_mode(true);
  Sniffer sniffer(conf.NAME, cfg);
  sniffer.sniff_loop([&](Packet &pkt)
  {
    PDU *pdu = pkt.pdu();
    if (!pdu) return true;
    IP &ip = pdu->rfind_pdu<IP>();

    // Write Pcap Log
    string date = currentDate();
    string path = getPath();
    if (currentDay != date)
    {
      currentDay = date;
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
    string protocol = "";
    uint16_t sport = 0;
    uint16_t dport = 0;

    // Define Protocol and Port
    if (TCP *tcp = pdu->find_pdu<TCP>())
    {
      sport = tcp->sport();
      dport = tcp->dport();
      protocol = tcp_define_protocol(conf, tcp);
    }
    if (UDP *udp = pdu->find_pdu<UDP>())
    {
      sport = udp->sport();
      dport = udp->dport();
      protocol = "udp";
    }
    if (ICMP *icmp = pdu->find_pdu<ICMP>())
    {
      protocol = "icmp";
    }



    string ip_key = define_ip_key(ip, conf);

    // HTTP
    if (protocol == "http")
    {
      follower.process_packet(pkt);
    }

    // ICMP Connect
    if (ICMP *icmp = pdu->find_pdu<ICMP>())
    {
      auto it_icmp = icmpConnectMap.find(ip_key);
      if (it_icmp != icmpConnectMap.end())
      {
        ICMP_Connect &icmp_connect = it_icmp->second;
        icmp_connect.packet_count++;
        icmp_connect.last_seen = SystemClock::now();

        auto duration = icmp_connect.last_seen - icmp_connect.first_seen;
        auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
        if (elapsed_seconds.count() > 0.0)
        {
          double pps = icmp_connect.packet_count / elapsed_seconds.count();
          if (pps > ICMP_PPS_LIMIT && icmp_connect.icmp_flood == false)
          {
            cout << "[ALERT] ICMP Flood DETECTED" << endl;
            icmp_connect.icmp_flood = true;
          }
          else
          {
            return true;
          }
        }
      }
      else
      {
        ICMP_Connect icmp_connect;
        icmp_connect.ip = ip_key;
        icmp_connect.first_seen = SystemClock::now();
        icmp_connect.last_seen = SystemClock::now();
        icmp_connect.packet_count++;

        icmpConnectMap[ip_key] = icmp_connect;
      }
    }

    // IP Connect (TCP Analysis)
    auto it_ip = ipConnectMap.find(ip_key);
    if (it_ip != ipConnectMap.end())
    {
      IP_Connect &ip_connect = it_ip->second;
      ip_connect.last_seen = SystemClock::now();

      // Reset Connection
      auto duration_check = ip_connect.last_seen - ip_connect.first_seen;
      if (chrono::duration_cast<chrono::seconds>(duration_check) > PORT_CONNECT_DURATION_LIMIT)
      {
        ip_connect.first_seen = SystemClock::now();
        ip_connect.port_list.clear();
        ip_connect.syn_count = 0;
        ip_connect.port_scan = false;
        ip_connect.syn_flood = false;
      }

      uint16_t port_connect = define_port_connect(pdu, ip_key);

      auto it = find(ip_connect.port_list.begin(), ip_connect.port_list.end(), port_connect);
      if (it == ip_connect.port_list.end())
      {
        ip_connect.port_list.push_back(port_connect);
      }

      if (TCP *tcp = pdu->find_pdu<TCP>())
      {
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == TCP::SYN)
        {
          ip_connect.syn_count++;
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 0)
        {
          cout << "[ALERT] NULL SCAN DETECTED" << endl;
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 63)
        {
          cout << "[ALERT] TCP FULL XMAS SCAN DETECTED" << endl;
        }
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == 56)
        {
          cout << "[ALERT] Standard Nmap Xmas Scan DETECTED" << endl;
        }
      }

      auto duration = ip_connect.last_seen - ip_connect.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      if (ip_connect.port_list.size() > PORT_CONNECT_LIMIT && elapsed_seconds <= PORT_CONNECT_DURATION_LIMIT)
      {
        if (ip_connect.port_scan == false)
        {
          cout << "[ALERT] PORT SCAN DETECTED (" << ip_connect.port_list.size() << " ports)" << endl;
          ip_connect.port_scan = true;
        }
      }

      // Alert SYN Flood
      if (ip_connect.syn_count > SYN_CONNECT_LIMIT && elapsed_seconds <= SYN_CONNECT_DURATION_LIMIT)
      {
        if (ip_connect.syn_flood == false)
        {
          cout << "[ALERT] SYN FLOOD DETECTED (Count: " << ip_connect.syn_count << ")" << endl;
          ip_connect.syn_flood = true;
        }

        // IPS Block
        if (!ip_connect.blocked && mode && ip_connect.syn_flood)
        {
          string block_command = "sudo iptables -A INPUT -s " + ip_connect.ip + " -j DROP";
          if (system(block_command.c_str()) == 0)
            cout << "[ACTION] SUCCESSFULLY BLOCKED IP: " << ip_connect.ip << endl;
          ip_connect.blocked = true;
        }
      }
    }
    else
    {
      // --- Create New ---
      IP_Connect ip_connect;
      ip_connect.ip = ip_key;
      ip_connect.first_seen = SystemClock::now();
      ip_connect.last_seen = SystemClock::now();
      uint16_t port_connect = define_port_connect(pdu, ip_key);
      ip_connect.port_list.push_back(port_connect);

      if (TCP *tcp = pdu->find_pdu<TCP>())
      {
        if (ip.src_addr().to_string() == ip_key && tcp->flags() == TCP::SYN)
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
    if (it_ip != ipConnectMap.end());

    auto it_udp = udpConnectMap.find(ip_key);
    if (it_udp != udpConnectMap.end())
    {
      // Update UDP Map
      UDP_Connect &udp_connect = it_udp->second;

      udp_connect.packet_count++;
      udp_connect.last_seen = SystemClock::now();

      uint16_t port_connect = define_port_connect(pdu, ip_key);
      auto it = find(udp_connect.port_list.begin(), udp_connect.port_list.end(), port_connect);
      if (it == udp_connect.port_list.end())
      {
        udp_connect.port_list.push_back(port_connect);
      }

      if (ip.src_addr().to_string() == ip_key)
      {
        if (!portList.count(port_connect))
        {
          udp_connect.unreach_count++;
        }
      }

      if (udp_connect.unreach_count > UNREACH_COUNT_LIMIT && udp_connect.udp_flood == false)
      {
        cout << "[ALERT] UDP Flood DETECTED" << endl;
        udp_connect.udp_flood = true;
      }
      else
      {
        return true;
      }

      auto duration = udp_connect.last_seen - udp_connect.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      if (elapsed_seconds.count() > 0)
      {
        if ((udp_connect.packet_count / elapsed_seconds.count()) > UDP_PPS_LIMIT && udp_connect.udp_flood == false)
        {
          cout << "[ALERT] UDP Flood DETECTED" << endl;
          udp_connect.udp_flood = true;
        }
        else
        {
          return true;
        }
      }
    }
    else
    {
      // Create UDP Map
      UDP_Connect udp_connect;
      udp_connect.ip = ip_key;
      udp_connect.first_seen = SystemClock::now();
      udp_connect.last_seen = SystemClock::now();
      udp_connect.packet_count = 1;

      uint16_t port_connect = define_port_connect(pdu, ip_key);
      udp_connect.port_list.push_back(port_connect);

      if (ip.src_addr().to_string() == ip_key)
      {
        if (!portList.count(udp->dport()))
        {
          udp_connect.unreach_count++;
        }
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
      SSH_State &ssh = it_ssh->second;
      ssh.last_seen = SystemClock::now();
      auto duration = ssh.last_seen - ssh.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      ssh_read_fail_state(BTMP_PATH, ssh);
      if (elapsed_seconds < SSH_DURATION_LIMIT && ssh.login_fail > SSH_LOGIN_FAIL_DURATION_LIMIT)
      {
        if (ssh.ssh_brute_force == false)
        {
          cout << "[ALERT] SSH BRUTE FORCE DETECTED (High Rate): " << ssh.ip << endl;
          ssh.ssh_brute_force = true;
        }
        else
        {
          return true;
        }

        // IPS
        if (ssh.blocked == false)
        {
          if (mode && ssh.ssh_brute_force)
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
      else if (ssh.login_fail > SSH_LOGIN_FAIL_LIMIT)
      {
        if (ssh.ssh_brute_force == false)
        {
          cout << "[ALERT] SSH BRUTE FORCE DETECTED (Total Limit): " << ssh.ip << endl;
          ssh.ssh_brute_force = true;
        }
        else
        {
          return true;
        }

        // IPS
        if (ssh.blocked == false)
        {
          if (mode && ssh.ssh_brute_force)
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
      FTP_State &ftp = it_ftp->second;
      ftp.last_seen = SystemClock::now();
      auto duration = ftp.last_seen - ftp.first_seen;
      auto elapsed_seconds = chrono::duration_cast<chrono::seconds>(duration);
      ftp_read_fail_state(VSFTPD_LOG_PATH, ftp);
      if (elapsed_seconds < FTP_DURATION_LIMIT && ftp.login_fail > FTP_LOGIN_FAIL_DURATION_LIMIT)
      {
        if (ftp.ftp_brute_force == false)
        {
          cout << "[ALERT] FTP BRUTE FORCE DETECTED" << endl;
          ftp.ftp_brute_force = true;
          try
          {
            auto time_t_val = chrono::system_clock::to_time_t(ftp.last_seen);
            stringstream ss;
            ss << put_time(localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");
            string log_time_str = ss.str();

            pqxx::work txn(conn);
            txn.exec_params(
              "INSERT INTO attack_logs (event_time, src_addr, src_port, dst_addr, dst_port, protocol, attack_type, response_type) "
              "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
              log_time_str, ip.src_addr().to_string(), sport, ip.dst_addr().to_string(), dport, protocol, "FTP Brute Force", "Alert"
            );
            txn.commit();
          }
          catch (const exception &e)
          {
            cerr << "DB Error: " << e.what() << endl;
            return true;
          }
        }
        else
        {
          return true;
        }

        // IPS
        if (ftp.blocked == false)
        {
          if (mode && ftp.ftp_brute_force)
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
      else if (ftp.login_fail > FTP_LOGIN_FAIL_LIMIT)
      {
        if (ftp.ftp_brute_force == false)
        {
          cout << "[ALERT] FTP BRUTE FORCE DETECTED (Total Limit): " << endl;
          ftp.ftp_brute_force = true;
          try
          {
            auto time_t_val = chrono::system_clock::to_time_t(ftp.last_seen);
            stringstream ss;
            ss << put_time(localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");
            string log_time_str = ss.str();

            pqxx::work txn(conn);
            txn.exec_params(
              "INSERT INTO attack_logs (event_time, src_addr, src_port, dst_addr, dst_port, protocol, attack_type, response_type) "
              "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
              log_time_str, ip.src_addr().to_string(), sport, ip.dst_addr().to_string(), dport, protocol, "FTP Brute Force", "Alert"
            );
            txn.commit();
          }
          catch (const exception &e)
          {
            cerr << "DB Error: " << e.what() << endl;
            return true;
          }
        }
        else
        {
          return true;
        }

        // IPS
        if (ftp.blocked == false)
        {
          if (mode && ftp.ftp_brute_force)
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

    clean_event_log(evenMap, IP_TIMEOUT);
    clean_ssh_state(sshMap, SSH_TIMEOUT);
    clean_ftp_state(ftpMap, FTP_TIMEOUT);
    clean_ip_connect(ipConnectMap, IP_PORT_CONNECT_TIMEOUT);
    clean_udp_connect(udpConnectMap, UDP_PORT_CONNECT_TIMEOUT);
    clean_icmp_connect(icmpConnectMap, ICMP_CONNECT_TIMEOUT);
    clean_http_state(httpMap, HTTP_TIMEOUT);
    return true; });
}

#endif