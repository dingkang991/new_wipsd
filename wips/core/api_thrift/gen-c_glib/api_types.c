/**
 * Autogenerated by Thrift Compiler (1.0.0-dev)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

#include <math.h>

#include "api_types.h"
#include <thrift/c_glib/thrift.h>

enum _ReportEventProperties
{
  PROP_REPORT_EVENT_0,
  PROP_REPORT_EVENT_EVENT_ID,
  PROP_REPORT_EVENT_EVENT_DESC,
  PROP_REPORT_EVENT_MAC,
  PROP_REPORT_EVENT_PEER_MAC
};

/* reads a report_event object */
static gint32
report_event_read (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;
  gchar *name = NULL;
  ThriftType ftype;
  gint16 fid;
  guint32 len = 0;
  gpointer data = NULL;
  ReportEvent * this_object = REPORT_EVENT(object);

  /* satisfy -Wall in case these aren't used */
  THRIFT_UNUSED_VAR (len);
  THRIFT_UNUSED_VAR (data);
  THRIFT_UNUSED_VAR (this_object);

  /* read the struct begin marker */
  if ((ret = thrift_protocol_read_struct_begin (protocol, &name, error)) < 0)
  {
    if (name) g_free (name);
    return -1;
  }
  xfer += ret;
  if (name) g_free (name);
  name = NULL;

  /* read the struct fields */
  while (1)
  {
    /* read the beginning of a field */
    if ((ret = thrift_protocol_read_field_begin (protocol, &name, &ftype, &fid, error)) < 0)
    {
      if (name) g_free (name);
      return -1;
    }
    xfer += ret;
    if (name) g_free (name);
    name = NULL;

    /* break if we get a STOP field */
    if (ftype == T_STOP)
    {
      break;
    }

    switch (fid)
    {
      case 1:
        if (ftype == T_I16)
        {
          if ((ret = thrift_protocol_read_i16 (protocol, &this_object->eventId, error)) < 0)
            return -1;
          xfer += ret;
          this_object->__isset_eventId = TRUE;
        } else {
          if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
            return -1;
          xfer += ret;
        }
        break;
      case 2:
        if (ftype == T_STRING)
        {
          if (this_object->eventDesc != NULL)
          {
            g_free(this_object->eventDesc);
            this_object->eventDesc = NULL;
          }

          if ((ret = thrift_protocol_read_string (protocol, &this_object->eventDesc, error)) < 0)
            return -1;
          xfer += ret;
          this_object->__isset_eventDesc = TRUE;
        } else {
          if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
            return -1;
          xfer += ret;
        }
        break;
      case 3:
        if (ftype == T_STRING)
        {
          if (this_object->mac != NULL)
          {
            g_free(this_object->mac);
            this_object->mac = NULL;
          }

          if ((ret = thrift_protocol_read_string (protocol, &this_object->mac, error)) < 0)
            return -1;
          xfer += ret;
          this_object->__isset_mac = TRUE;
        } else {
          if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
            return -1;
          xfer += ret;
        }
        break;
      case 4:
        if (ftype == T_STRING)
        {
          if (this_object->peerMac != NULL)
          {
            g_free(this_object->peerMac);
            this_object->peerMac = NULL;
          }

          if ((ret = thrift_protocol_read_string (protocol, &this_object->peerMac, error)) < 0)
            return -1;
          xfer += ret;
          this_object->__isset_peerMac = TRUE;
        } else {
          if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
            return -1;
          xfer += ret;
        }
        break;
      default:
        if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
          return -1;
        xfer += ret;
        break;
    }
    if ((ret = thrift_protocol_read_field_end (protocol, error)) < 0)
      return -1;
    xfer += ret;
  }

  if ((ret = thrift_protocol_read_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static gint32
report_event_write (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;

  ReportEvent * this_object = REPORT_EVENT(object);
  THRIFT_UNUSED_VAR (this_object);
  if ((ret = thrift_protocol_write_struct_begin (protocol, "ReportEvent", error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_begin (protocol, "eventId", T_I16, 1, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_i16 (protocol, this_object->eventId, error)) < 0)
    return -1;
  xfer += ret;

  if ((ret = thrift_protocol_write_field_end (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_begin (protocol, "eventDesc", T_STRING, 2, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_string (protocol, this_object->eventDesc, error)) < 0)
    return -1;
  xfer += ret;

  if ((ret = thrift_protocol_write_field_end (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_begin (protocol, "mac", T_STRING, 3, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_string (protocol, this_object->mac, error)) < 0)
    return -1;
  xfer += ret;

  if ((ret = thrift_protocol_write_field_end (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_begin (protocol, "peerMac", T_STRING, 4, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_string (protocol, this_object->peerMac, error)) < 0)
    return -1;
  xfer += ret;

  if ((ret = thrift_protocol_write_field_end (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_stop (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static void
report_event_set_property (GObject *object,
                           guint property_id,
                           const GValue *value,
                           GParamSpec *pspec)
{
  ReportEvent *self = REPORT_EVENT (object);

  switch (property_id)
  {
    case PROP_REPORT_EVENT_EVENT_ID:
      self->eventId = g_value_get_int (value);
      self->__isset_eventId = TRUE;
      break;

    case PROP_REPORT_EVENT_EVENT_DESC:
      if (self->eventDesc != NULL)
        g_free (self->eventDesc);
      self->eventDesc = g_value_dup_string (value);
      self->__isset_eventDesc = TRUE;
      break;

    case PROP_REPORT_EVENT_MAC:
      if (self->mac != NULL)
        g_free (self->mac);
      self->mac = g_value_dup_string (value);
      self->__isset_mac = TRUE;
      break;

    case PROP_REPORT_EVENT_PEER_MAC:
      if (self->peerMac != NULL)
        g_free (self->peerMac);
      self->peerMac = g_value_dup_string (value);
      self->__isset_peerMac = TRUE;
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void
report_event_get_property (GObject *object,
                           guint property_id,
                           GValue *value,
                           GParamSpec *pspec)
{
  ReportEvent *self = REPORT_EVENT (object);

  switch (property_id)
  {
    case PROP_REPORT_EVENT_EVENT_ID:
      g_value_set_int (value, self->eventId);
      break;

    case PROP_REPORT_EVENT_EVENT_DESC:
      g_value_set_string (value, self->eventDesc);
      break;

    case PROP_REPORT_EVENT_MAC:
      g_value_set_string (value, self->mac);
      break;

    case PROP_REPORT_EVENT_PEER_MAC:
      g_value_set_string (value, self->peerMac);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void 
report_event_instance_init (ReportEvent * object)
{
  /* satisfy -Wall */
  THRIFT_UNUSED_VAR (object);
  object->eventId = 0;
  object->__isset_eventId = FALSE;
  object->eventDesc = NULL;
  object->__isset_eventDesc = FALSE;
  object->mac = NULL;
  object->__isset_mac = FALSE;
  object->peerMac = NULL;
  object->__isset_peerMac = FALSE;
}

static void 
report_event_finalize (GObject *object)
{
  ReportEvent *tobject = REPORT_EVENT (object);

  /* satisfy -Wall in case we don't use tobject */
  THRIFT_UNUSED_VAR (tobject);
  if (tobject->eventDesc != NULL)
  {
    g_free(tobject->eventDesc);
    tobject->eventDesc = NULL;
  }
  if (tobject->mac != NULL)
  {
    g_free(tobject->mac);
    tobject->mac = NULL;
  }
  if (tobject->peerMac != NULL)
  {
    g_free(tobject->peerMac);
    tobject->peerMac = NULL;
  }
}

static void
report_event_class_init (ReportEventClass * cls)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (cls);
  ThriftStructClass *struct_class = THRIFT_STRUCT_CLASS (cls);

  struct_class->read = report_event_read;
  struct_class->write = report_event_write;

  gobject_class->finalize = report_event_finalize;
  gobject_class->get_property = report_event_get_property;
  gobject_class->set_property = report_event_set_property;

  g_object_class_install_property
    (gobject_class,
     PROP_REPORT_EVENT_EVENT_ID,
     g_param_spec_int ("eventId",
                       NULL,
                       NULL,
                       G_MININT16,
                       G_MAXINT16,
                       0,
                       G_PARAM_READWRITE));

  g_object_class_install_property
    (gobject_class,
     PROP_REPORT_EVENT_EVENT_DESC,
     g_param_spec_string ("eventDesc",
                          NULL,
                          NULL,
                          NULL,
                          G_PARAM_READWRITE));

  g_object_class_install_property
    (gobject_class,
     PROP_REPORT_EVENT_MAC,
     g_param_spec_string ("mac",
                          NULL,
                          NULL,
                          NULL,
                          G_PARAM_READWRITE));

  g_object_class_install_property
    (gobject_class,
     PROP_REPORT_EVENT_PEER_MAC,
     g_param_spec_string ("peerMac",
                          NULL,
                          NULL,
                          NULL,
                          G_PARAM_READWRITE));
}

GType
report_event_get_type (void)
{
  static GType type = 0;

  if (type == 0) 
  {
    static const GTypeInfo type_info = 
    {
      sizeof (ReportEventClass),
      NULL, /* base_init */
      NULL, /* base_finalize */
      (GClassInitFunc) report_event_class_init,
      NULL, /* class_finalize */
      NULL, /* class_data */
      sizeof (ReportEvent),
      0, /* n_preallocs */
      (GInstanceInitFunc) report_event_instance_init,
      NULL, /* value_table */
    };

    type = g_type_register_static (THRIFT_TYPE_STRUCT, 
                                   "ReportEventType",
                                   &type_info, 0);
  }

  return type;
}

/* constants */

enum _ReportEventServiceReportArgsProperties
{
  PROP_REPORT_EVENT_SERVICE_REPORT_ARGS_0,
  PROP_REPORT_EVENT_SERVICE_REPORT_ARGS_E
};

/* reads a report_event_service_report_args object */
static gint32
report_event_service_report_args_read (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;
  gchar *name = NULL;
  ThriftType ftype;
  gint16 fid;
  guint32 len = 0;
  gpointer data = NULL;
  ReportEventServiceReportArgs * this_object = REPORT_EVENT_SERVICE_REPORT_ARGS(object);

  /* satisfy -Wall in case these aren't used */
  THRIFT_UNUSED_VAR (len);
  THRIFT_UNUSED_VAR (data);
  THRIFT_UNUSED_VAR (this_object);

  /* read the struct begin marker */
  if ((ret = thrift_protocol_read_struct_begin (protocol, &name, error)) < 0)
  {
    if (name) g_free (name);
    return -1;
  }
  xfer += ret;
  if (name) g_free (name);
  name = NULL;

  /* read the struct fields */
  while (1)
  {
    /* read the beginning of a field */
    if ((ret = thrift_protocol_read_field_begin (protocol, &name, &ftype, &fid, error)) < 0)
    {
      if (name) g_free (name);
      return -1;
    }
    xfer += ret;
    if (name) g_free (name);
    name = NULL;

    /* break if we get a STOP field */
    if (ftype == T_STOP)
    {
      break;
    }

    switch (fid)
    {
      case 1:
        if (ftype == T_STRUCT)
        {
          if ((ret = thrift_struct_read (THRIFT_STRUCT (this_object->e), protocol, error)) < 0)
          {
            return -1;
          }
          xfer += ret;
          this_object->__isset_e = TRUE;
        } else {
          if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
            return -1;
          xfer += ret;
        }
        break;
      default:
        if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
          return -1;
        xfer += ret;
        break;
    }
    if ((ret = thrift_protocol_read_field_end (protocol, error)) < 0)
      return -1;
    xfer += ret;
  }

  if ((ret = thrift_protocol_read_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static gint32
report_event_service_report_args_write (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;

  ReportEventServiceReportArgs * this_object = REPORT_EVENT_SERVICE_REPORT_ARGS(object);
  THRIFT_UNUSED_VAR (this_object);
  if ((ret = thrift_protocol_write_struct_begin (protocol, "ReportEventServiceReportArgs", error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_begin (protocol, "e", T_STRUCT, 1, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_struct_write (THRIFT_STRUCT (this_object->e), protocol, error)) < 0)
    return -1;
  xfer += ret;

  if ((ret = thrift_protocol_write_field_end (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_stop (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static void
report_event_service_report_args_set_property (GObject *object,
                                               guint property_id,
                                               const GValue *value,
                                               GParamSpec *pspec)
{
  ReportEventServiceReportArgs *self = REPORT_EVENT_SERVICE_REPORT_ARGS (object);

  switch (property_id)
  {
    case PROP_REPORT_EVENT_SERVICE_REPORT_ARGS_E:
      if (self->e != NULL)
        g_object_unref (self->e);
      self->e = g_value_dup_object (value);
      self->__isset_e = TRUE;
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void
report_event_service_report_args_get_property (GObject *object,
                                               guint property_id,
                                               GValue *value,
                                               GParamSpec *pspec)
{
  ReportEventServiceReportArgs *self = REPORT_EVENT_SERVICE_REPORT_ARGS (object);

  switch (property_id)
  {
    case PROP_REPORT_EVENT_SERVICE_REPORT_ARGS_E:
      g_value_set_object (value, self->e);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static void 
report_event_service_report_args_instance_init (ReportEventServiceReportArgs * object)
{
  /* satisfy -Wall */
  THRIFT_UNUSED_VAR (object);
  object->e = g_object_new (TYPE_REPORT_EVENT, NULL);
  object->__isset_e = FALSE;
}

static void 
report_event_service_report_args_finalize (GObject *object)
{
  ReportEventServiceReportArgs *tobject = REPORT_EVENT_SERVICE_REPORT_ARGS (object);

  /* satisfy -Wall in case we don't use tobject */
  THRIFT_UNUSED_VAR (tobject);
  if (tobject->e != NULL)
  {
    g_object_unref(tobject->e);
    tobject->e = NULL;
  }
}

static void
report_event_service_report_args_class_init (ReportEventServiceReportArgsClass * cls)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (cls);
  ThriftStructClass *struct_class = THRIFT_STRUCT_CLASS (cls);

  struct_class->read = report_event_service_report_args_read;
  struct_class->write = report_event_service_report_args_write;

  gobject_class->finalize = report_event_service_report_args_finalize;
  gobject_class->get_property = report_event_service_report_args_get_property;
  gobject_class->set_property = report_event_service_report_args_set_property;

  g_object_class_install_property
    (gobject_class,
     PROP_REPORT_EVENT_SERVICE_REPORT_ARGS_E,
     g_param_spec_object ("e",
                         NULL,
                         NULL,
                         TYPE_REPORT_EVENT,
                         G_PARAM_READWRITE));
}

GType
report_event_service_report_args_get_type (void)
{
  static GType type = 0;

  if (type == 0) 
  {
    static const GTypeInfo type_info = 
    {
      sizeof (ReportEventServiceReportArgsClass),
      NULL, /* base_init */
      NULL, /* base_finalize */
      (GClassInitFunc) report_event_service_report_args_class_init,
      NULL, /* class_finalize */
      NULL, /* class_data */
      sizeof (ReportEventServiceReportArgs),
      0, /* n_preallocs */
      (GInstanceInitFunc) report_event_service_report_args_instance_init,
      NULL, /* value_table */
    };

    type = g_type_register_static (THRIFT_TYPE_STRUCT, 
                                   "ReportEventServiceReportArgsType",
                                   &type_info, 0);
  }

  return type;
}

/* reads a report_event_service_report_result object */
static gint32
report_event_service_report_result_read (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;
  gchar *name = NULL;
  ThriftType ftype;
  gint16 fid;
  guint32 len = 0;
  gpointer data = NULL;
  ReportEventServiceReportResult * this_object = REPORT_EVENT_SERVICE_REPORT_RESULT(object);

  /* satisfy -Wall in case these aren't used */
  THRIFT_UNUSED_VAR (len);
  THRIFT_UNUSED_VAR (data);
  THRIFT_UNUSED_VAR (this_object);

  /* read the struct begin marker */
  if ((ret = thrift_protocol_read_struct_begin (protocol, &name, error)) < 0)
  {
    if (name) g_free (name);
    return -1;
  }
  xfer += ret;
  if (name) g_free (name);
  name = NULL;

  /* read the struct fields */
  while (1)
  {
    /* read the beginning of a field */
    if ((ret = thrift_protocol_read_field_begin (protocol, &name, &ftype, &fid, error)) < 0)
    {
      if (name) g_free (name);
      return -1;
    }
    xfer += ret;
    if (name) g_free (name);
    name = NULL;

    /* break if we get a STOP field */
    if (ftype == T_STOP)
    {
      break;
    }

    switch (fid)
    {
      default:
        if ((ret = thrift_protocol_skip (protocol, ftype, error)) < 0)
          return -1;
        xfer += ret;
        break;
    }
    if ((ret = thrift_protocol_read_field_end (protocol, error)) < 0)
      return -1;
    xfer += ret;
  }

  if ((ret = thrift_protocol_read_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static gint32
report_event_service_report_result_write (ThriftStruct *object, ThriftProtocol *protocol, GError **error)
{
  gint32 ret;
  gint32 xfer = 0;

  ReportEventServiceReportResult * this_object = REPORT_EVENT_SERVICE_REPORT_RESULT(object);
  THRIFT_UNUSED_VAR (this_object);
  if ((ret = thrift_protocol_write_struct_begin (protocol, "ReportEventServiceReportResult", error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_field_stop (protocol, error)) < 0)
    return -1;
  xfer += ret;
  if ((ret = thrift_protocol_write_struct_end (protocol, error)) < 0)
    return -1;
  xfer += ret;

  return xfer;
}

static void 
report_event_service_report_result_instance_init (ReportEventServiceReportResult * object)
{
  /* satisfy -Wall */
  THRIFT_UNUSED_VAR (object);
}

static void 
report_event_service_report_result_finalize (GObject *object)
{
  ReportEventServiceReportResult *tobject = REPORT_EVENT_SERVICE_REPORT_RESULT (object);

  /* satisfy -Wall in case we don't use tobject */
  THRIFT_UNUSED_VAR (tobject);
}

static void
report_event_service_report_result_class_init (ReportEventServiceReportResultClass * cls)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (cls);
  ThriftStructClass *struct_class = THRIFT_STRUCT_CLASS (cls);

  struct_class->read = report_event_service_report_result_read;
  struct_class->write = report_event_service_report_result_write;

  gobject_class->finalize = report_event_service_report_result_finalize;
}

GType
report_event_service_report_result_get_type (void)
{
  static GType type = 0;

  if (type == 0) 
  {
    static const GTypeInfo type_info = 
    {
      sizeof (ReportEventServiceReportResultClass),
      NULL, /* base_init */
      NULL, /* base_finalize */
      (GClassInitFunc) report_event_service_report_result_class_init,
      NULL, /* class_finalize */
      NULL, /* class_data */
      sizeof (ReportEventServiceReportResult),
      0, /* n_preallocs */
      (GInstanceInitFunc) report_event_service_report_result_instance_init,
      NULL, /* value_table */
    };

    type = g_type_register_static (THRIFT_TYPE_STRUCT, 
                                   "ReportEventServiceReportResultType",
                                   &type_info, 0);
  }

  return type;
}

