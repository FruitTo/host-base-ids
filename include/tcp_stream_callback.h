#ifndef TCP_STREAM_CALLBACK_H
#define TCP_STREAM_CALLBACK_H

#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h>

using namespace Tins;
using namespace std;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

// Forward (client -> server)
void on_client_data(Stream& stream) {
    const Stream::payload_type& payload = stream.client_payload();
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
