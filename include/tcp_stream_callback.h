#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>
#include <regex>

using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

// Broken Access Control Patterns
regex path_traversal_regex(R"(((\.|%2e){2,}(\/|\\|%2f|%5c)){3,})");
regex lfi_regex(R"(/etc/(passwd|shadow|hosts)|[c-zc-z]:\\windows)");

// Forward (client -> server)
void on_client_data(Stream& stream) {
  const Stream::payload_type& payload = stream.client_payload();
  string data(payload.begin(), payload.end());

  string lower_data = data;
  transform(lower_data.begin(), lower_data.end(), lower_data.begin(), ::tolower);

  if (regex_search(lower_data, path_traversal_regex))
  {
    cout << "[ALERT] Directory Traversal Attack Detected! (Pattern: ../../../)" << endl;
    cout << "From IP: " << stream.client_addr_v4() << endl;
  }
  if (regex_search(lower_data, lfi_regex))
  {
    cout << "[ALERT] System File Access Attempt (LFI) Detected!" << endl;
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
