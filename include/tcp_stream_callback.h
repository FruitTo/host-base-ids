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

string url_decode(const string &encoded)
{
  int output_length;
  const auto decoded_value = curl_easy_unescape(nullptr, encoded.c_str(), static_cast<int>(encoded.length()), &output_length);
  string result(decoded_value, output_length);
  curl_free(decoded_value);
  return result;
}

// Forward (client -> server)
void on_client_data(Stream &stream)
{
  const Stream::payload_type &payload = stream.client_payload();
  string data(payload.begin(), payload.end());
  string decoded_data = url_decode(data);
  smatch match;

  string lower_data = decoded_data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);

  // Broken Access Control
  regex path_traversal_pattern(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
  if (regex_search(lower_data, path_traversal_pattern))
  {
    cout << "[ALERT] Directory Traversal Attack Detected! (Pattern: ../../../)" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex lfi_pattern(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");
  if (regex_search(lower_data, lfi_pattern))
  {
    cout << "[ALERT] System File Access Attempt (LFI) Detected!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }

  // SQL Injection
  regex sql_comment_pattern(R"((--[ \t'"+])|(/\*.*\*/(?!\*)))"); // Comment
  if (regex_search(lower_data, sql_comment_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Comment Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex and_or_pattern(R"(\b(and|or)(?:[\s\+]+|/\*.*?\*/|['"(])+\w*['"]?[\s\+]*(?:!=|>=|<=|=|>|<|like)+[\s\+]*['"]?\w*['")]?)"); // AND OR
  if (regex_search(lower_data, and_or_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL AND, OR Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex union_pattern(R"(\bunion([\s\+]+|/\*.*?\*/|\()+?(all([\s\+]+|/\*.*?\*/)+)?select\b)"); // UNION
  if (regex_search(lower_data, union_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Union Injection" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex call_func_pattern(R"(\b(sleep|benchmark|extractvalue|updatexml|load_file|pg_sleep|user|database|version|schema|current_user|system_user|group_concat|concat_ws|hex|unhex|geometrycollection|polygon|multipoint|linestring|pg_read_file|pg_ls_dir|xp_cmdshell)[\s\+]*\(.*\))"); // Function
  if (regex_search(lower_data, call_func_pattern))
  {
    cout << lower_data << endl;
    cout << "[ALERT] SQL Call DB Function" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }

  // Cross Site Scripting
  regex check_script_pattern(R"(<script([^>]*)>([\s\S\+]*?)<\/script>)");
  auto words_begin = sregex_iterator(lower_data.begin(), lower_data.end(), check_script_pattern);
  auto words_end = sregex_iterator();
  for (sregex_iterator i = words_begin; i != words_end; ++i)
  {
    smatch match = *i;
    string script_attr = match[1].str();
    string script_body = match[2].str();
    regex check_src_pattern(R"(src[\s\+/]*=[\s\+/]*['"]?[\s\+]*(https?:|\/\/|data:|javascript:))");
    if (regex_search(script_attr, check_src_pattern))
    {
      cout << "[ALERT] XSS Detected (External Source)!" << endl;
      cout << "Attribute: " << script_attr << endl;
      cout << "From IP: " << stream.client_addr_v4() << endl;
    }
    regex js_payload(R"((document\.cookie|localstorage\.getitem|fetch[\s\+]*\(|document\.location|history\.replacestate|document\.write|window\.location|eval[\s\+]*\(|document\.onkeypress|alert[\s\+]*\(|prompt[\s\+]*\(|confirm[\s\+]*\())");
    if (regex_search(script_body, js_payload))
    {
      cout << "[ALERT] XSS Detected (Dangerous Payload)!" << endl;
      cout << "Payload: " << script_body << endl;
      cout << "From IP: " << stream.client_addr_v4() << endl;
    }
  }
  regex check_event_pattern(R"([\s/\"'+>]+on(load|error|mouseover|focus|click|submit|keypress|change|input|mouseenter|mouseleave)[\s\+]*=[\s\+]*)");
  if (regex_search(lower_data, check_event_pattern))
  {
    cout << "[ALERT] XSS Detected (Event Handler Injection)!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  regex check_pseudo_protocol(R"((src|href|action|formaction)[\s\+/]*=[\s\+/]*['"]?[\s\+]*(javascript:|vbscript:|data:text\/html))");
  if (regex_search(lower_data, check_pseudo_protocol))
  {
    cout << "[ALERT] XSS Detected (Malicious Protocol)!" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
}

// Backward (server -> client)
void on_server_data(Stream &stream)
{
}

void on_new_stream(Stream &stream)
{
  stream.client_data_callback(&on_client_data);
  stream.server_data_callback(&on_server_data);
  stream.auto_cleanup_client_data(true);
  stream.auto_cleanup_server_data(true);
  stream.auto_cleanup_payloads(true);
}

void on_stream_terminated(Stream &stream, StreamFollower::TerminationReason reason)
{
}

#endif