#include <iostream>
#include <string>
#include <regex>

using namespace std;

int main() {
  regex sql_comment(R"((--\s|--\+)|(#)|(/\*.*\*/))");
  regex patttern(R"()");

  if(regex_search(req, patttern)) {
    cout << "Alert This is SQL INJECTION !!!!" << endl;
  }

  return 0;
}