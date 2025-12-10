#ifndef DEFINE_PROTOCOL_H
#define DEFINE_PROTOCOL_H

#include <tins/tins.h>
#include <tins/tcp.h>
#include <string>

#include "./network_config.h"

using namespace std;
using namespace Tins;
using Tins::TCP;

string tcp_define_protocol(NetworkConfig &conf, Tins::TCP *tcp)
{
  // HTTP
  for (const string &port_str : conf.HTTP_PORTS)
  {
    int port = stoi(port_str);
    if (tcp->dport() == port)
    {
      return "http";
    }
  }
  if (tcp->sport() == 80 || tcp->dport() == 80){
      return "http";
  }

  // SSH
  for (const string &port_str : conf.SSH_PORTS)
  {
    int port = stoi(port_str);
    if (tcp->dport() == port)
    {
      return "ssh";
    }
  }
  if(tcp->sport() == 22 || tcp->dport() == 22){
    return "ssh";
  }

  // FTP
  for (const string &port_str : conf.FTP_PORTS)
  {
    int port = stoi(port_str);
    if (tcp->dport() == port)
    {
      return "ftp";
    }
  }
  if(tcp->sport() == 21 || tcp->dport() == 21){
    return "ftp";
  }

  return "";
}

#endif
