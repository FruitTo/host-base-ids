#ifndef DB_CONNECT_H
#define DB_CONNECT_H

#include <iostream>
#include <string>

using namespace std;

string db_connect() {
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

  try{
    pqxx::connection conn(conninfo);
    if (!conn.is_open()) {
      cerr << "Connection object exists but is not open.\n";
      return "";
    }
    cout << "Connected to DB: " << conn.dbname() << "\n";
    return conninfo;
  } catch (const exception &e) {
    cerr << e.what() << endl;
    return "";
  }
}


#endif