#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>
#include <regex>
#include <string>
#include <iostream>
#include <curl/curl.h>
using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

string url_encode(const string& decoded)
{
    const auto encoded_value = curl_easy_escape(nullptr, decoded.c_str(), static_cast<int>(decoded.length()));
    std::string result(encoded_value);
    curl_free(encoded_value);
    return result;
}

string url_decode(const string& encoded)
{
    int output_length;
    const auto decoded_value = curl_easy_unescape(nullptr, encoded.c_str(), static_cast<int>(encoded.length()), &output_length);
    std::string result(decoded_value, output_length);
    curl_free(decoded_value);
    return result;
}

// Forward (client -> server)
void on_client_data(Stream& stream) {
  const Stream::payload_type& payload = stream.client_payload();
  string data(payload.begin(), payload.end());
  string decoded_data = url_decode(data);

  string lower_data = decoded_data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);

  // Broken Access Control
  regex path_traversal_regex(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  if (regex_search(lower_data, path_traversal_regex))
  {
    cout << "[ALERT] Directory Traversal Attack Detected! (Pattern: ../../../)" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex lfi_regex(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");
  if (regex_search(lower_data, lfi_regex))
  {
    cout << "[ALERT] System File Access Attempt (LFI) Detected!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }

  // SQL Injection
  regex sql_comment(R"((--[ \t'"+])|(/\*.*\*/(?!\*)))");    // Comment
  if (regex_search(lower_data, sql_comment))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Comment Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex and_or_pattern(R"(\b(and|or)(?:\s+|/\*.*?\*/|['"(])+\w*['"]?\s*(?:!=|>=|<=|=|>|<|like)+\s*['"]?\w*['")]?)");          // AND OR
  if (regex_search(lower_data, and_or_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL AND, OR Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex union_pattern(R"(\bunion(\s+|/\*.*?\*/|\()+?(all(\s+|/\*.*?\*/)+)?select\b)");              // UNION
  if (regex_search(lower_data, union_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Union Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex call_func(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)\s*\(.*\))");              // Function
  if (regex_search(lower_data, call_func))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Call DB Function" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
}

// Backward (server -> client)
void on_server_data(Stream& stream) {
}

void on_new_stream(Stream& stream)
{
  stream.client_data_callback(&on_client_data);
  stream.server_data_callback(&on_server_data);
  stream.auto_cleanup_client_data(true);
  stream.auto_cleanup_server_data(true);
  stream.auto_cleanup_payloads(true);
}

void on_stream_terminated(Stream& stream, StreamFollower::TerminationReason reason)
{

}

#endif
