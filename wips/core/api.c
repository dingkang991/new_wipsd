#include <stdio.h>
#include <glib-object.h>

#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_socket.h>


#include <thrift/c_glib/thrift.h>
#include <thrift/c_glib/protocol/thrift_binary_protocol.h>
#include <thrift/c_glib/protocol/thrift_compact_protocol.h>
#include <thrift/c_glib/protocol/thrift_multiplexed_protocol.h>
#include <thrift/c_glib/transport/thrift_buffered_transport.h>
#include <thrift/c_glib/transport/thrift_framed_transport.h>
#include <thrift/c_glib/transport/thrift_ssl_socket.h>
#include <thrift/c_glib/transport/thrift_socket.h>
#include <thrift/c_glib/transport/thrift_transport.h>


#include "gen-c_glib/report_event_service.h"
#include "gen-c_glib/api_types.h"
#include "common.h"
#include "api.h"
#if 1
ThriftProtocol *
get_multiplexed_protocol(gchar *protocol_name, ThriftTransport *transport, gchar *service_name)
{
  ThriftProtocol * multiplexed_protocol = NULL;

  if ( strncmp(protocol_name, "binary:", 7) == 0) {
    multiplexed_protocol = g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                 "transport", transport,
                 NULL);
  } else if ( strncmp(protocol_name, "compact:", 8) == 0) {
    multiplexed_protocol = g_object_new (THRIFT_TYPE_COMPACT_PROTOCOL,
                 "transport", transport,
                 NULL);
  } else {
    fprintf(stderr, "Unknown multiplex protocol name: %s\n", protocol_name);
    return NULL;
  }

  return g_object_new (THRIFT_TYPE_MULTIPLEXED_PROTOCOL,
          "transport",      transport,
          "protocol",       multiplexed_protocol,
          "service-name",   service_name,
          NULL);
}

#endif
int eventReport (eventReport_t *e)
{
  ThriftSocket *socket;
  ThriftTransport *transport;
  ThriftProtocol *protocol;
  ReportEventServiceIf *client;

  GError *error = NULL;
  ReportEvent *eventOut = NULL;

  int exit_status = 0;

#if (!GLIB_CHECK_VERSION (2, 36, 0))
  g_type_init ();
#endif

  socket    = g_object_new (THRIFT_TYPE_SOCKET,
                            "hostname",  "192.168.0.30",
                            "port",      9091,
                            NULL);
  transport = g_object_new (THRIFT_TYPE_FRAMED_TRANSPORT,
                            "transport", socket,
                            NULL);
  #if 1
  
  protocol = get_multiplexed_protocol("binary:multi", transport, "api");
  if (NULL == protocol) {
	g_clear_object (&transport);
	g_clear_object (&socket);
	return -1;
  }
  #else
  protocol  = g_object_new (THRIFT_TYPE_BINARY_PROTOCOL,
                            "transport", transport,
                            NULL);
#endif
  thrift_transport_open (transport, &error);


  client = g_object_new (TYPE_REPORT_EVENT_SERVICE_CLIENT,
                         "input_protocol",  protocol,
                         "output_protocol", protocol,
                         NULL);

  
  eventOut = g_object_new (TYPE_REPORT_EVENT,
							 "eventId", e->eventId,
							 "eventDesc",		  e->eventDesc,
							 "mac",		 e->mac,
							 "peerMac",	   e->peerMac,
							 NULL);

  if (report_event_service_if_report (client,
										 eventOut,
										 &error)) {

	log_info_api("send event success\n");
  
  
  }else {
	log_error_api ("thrift send mesg error:%s\n", error->message);
	g_error_free (error);
	error = NULL;
	exit_status = -1;
  }

  g_object_unref (eventOut);


  thrift_transport_close (transport, NULL);

  g_object_unref (client);
  g_object_unref (protocol);
  g_object_unref (transport);
  g_object_unref (socket);

  return exit_status;
}

