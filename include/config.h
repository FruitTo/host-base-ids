#ifndef CONFIG_H
#define CONFIG_H
#include <string>

using namespace std;

struct AppConfig
{
  std::chrono::seconds ip_timeout{10};
  std::chrono::seconds ssh_timeout{30};
  std::chrono::seconds ftp_timeout{30};
  std::chrono::seconds http_timeout{30};
  std::chrono::seconds ip_port_connect_timeout{30};
  std::chrono::seconds udp_port_connect_timeout{30};
  std::chrono::seconds icmp_connect_timeout{30};
  std::chrono::minutes block_timeout{1};

  double icmp_pps_limit = 100.0;
  int port_connect_limit = 80;
  std::chrono::seconds port_connect_duration_limit{30};
  int syn_connect_limit = 10000;
  std::chrono::seconds syn_connect_duration_limit{30};
  int unreach_count_limit = 30;
  int udp_pps_limit = 10000;

  int ssh_login_fail_limit = 10;
  int ssh_login_fail_duration_limit = 100;
  std::chrono::seconds ssh_duration_limit{60};

  int ftp_login_fail_limit = 10;
  int ftp_login_fail_duration_limit = 100;
  std::chrono::seconds ftp_duration_limit{60};

  std::string btmp_path = "/var/log/btmp";
  std::string vsftpd_log_path = "/var/log/vsftpd.log";
};

#endif