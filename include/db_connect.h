#ifndef DB_CONNECT_H
#define DB_CONNECT_H

#include <iostream>
#include <string>

using namespace std;

string db_connect()
{
  string user, password, host, port, dbname;

  cout << "Postgres User: ";
  cin >> user;

  cout << "\nPostgres Password: ";
  cin >> password;

  cout << "\nPostgres Database Name: ";
  cin >> dbname;

  cout << "\nPostgres Host: ";
  cin >> host;

  cout << "\nPostgres Port: ";
  cin >> port;
  cin.get();
  cout << endl;

  string conninfo =
      "user=" + user +
      " password=" + password +
      " host=" + host +
      " port=" + port +
      " dbname=" + dbname +
      " target_session_attrs=read-write";

  try
  {
    pqxx::connection conn(conninfo);
    if (!conn.is_open())
    {
      cerr << "Connection object exists but is not open.\n";
      return "";
    }
    cout << "Connected to DB: " << conn.dbname() << "\n";
    return conninfo;
  }
  catch (const exception &e)
  {
    cerr << e.what() << endl;
    return "";
  }
}

void log_attack_to_db(pqxx::connection &conn,
                      const string &c_ip, int c_port,
                      const string &s_ip, int s_port,
                      const string &proto,
                      const string &attack_type,
                      const string &details)
{
  try
  {
    auto time_t_val = chrono::system_clock::to_time_t(chrono::system_clock::now());
    stringstream ss;
    ss << put_time(localtime(&time_t_val), "%Y-%m-%d %H:%M:%S");
    string log_time_str = ss.str();

    pqxx::work txn(conn);
    txn.exec_params(
        "INSERT INTO attack_logs (event_time, src_addr, src_port, dst_addr, dst_port, protocol, attack_type, response_type) "
        "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        log_time_str, c_ip, c_port, s_ip, s_port, proto, attack_type, details);
    txn.commit();
  }
  catch (const exception &e)
  {
    cerr << "DB Log Error: " << e.what() << endl;
  }
}

#endif