/**
 * Autogenerated by Thrift Compiler (1.0.0-dev)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#ifndef SHARED_TYPES_H
#define SHARED_TYPES_H

/* base includes */
#include <glib-object.h>
#include <thrift/c_glib/thrift_struct.h>
#include <thrift/c_glib/protocol/thrift_protocol.h>

/* custom thrift includes */

/* begin types */

/* struct SharedStruct */
struct _SharedStruct
{ 
  ThriftStruct parent; 

  /* public */
  gint32 key;
  gboolean __isset_key;
  gchar * value;
  gboolean __isset_value;
};
typedef struct _SharedStruct SharedStruct;

struct _SharedStructClass
{
  ThriftStructClass parent;
};
typedef struct _SharedStructClass SharedStructClass;

GType shared_struct_get_type (void);
#define TYPE_SHARED_STRUCT (shared_struct_get_type())
#define SHARED_STRUCT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), TYPE_SHARED_STRUCT, SharedStruct))
#define SHARED_STRUCT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), _TYPE_SHARED_STRUCT, SharedStructClass))
#define IS_SHARED_STRUCT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TYPE_SHARED_STRUCT))
#define IS_SHARED_STRUCT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), TYPE_SHARED_STRUCT))
#define SHARED_STRUCT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), TYPE_SHARED_STRUCT, SharedStructClass))

/* constants */

/* struct SharedServiceGetStructArgs */
struct _SharedServiceGetStructArgs
{ 
  ThriftStruct parent; 

  /* public */
  gint32 key;
  gboolean __isset_key;
};
typedef struct _SharedServiceGetStructArgs SharedServiceGetStructArgs;

struct _SharedServiceGetStructArgsClass
{
  ThriftStructClass parent;
};
typedef struct _SharedServiceGetStructArgsClass SharedServiceGetStructArgsClass;

GType shared_service_get_struct_args_get_type (void);
#define TYPE_SHARED_SERVICE_GET_STRUCT_ARGS (shared_service_get_struct_args_get_type())
#define SHARED_SERVICE_GET_STRUCT_ARGS(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_ARGS, SharedServiceGetStructArgs))
#define SHARED_SERVICE_GET_STRUCT_ARGS_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), _TYPE_SHARED_SERVICE_GET_STRUCT_ARGS, SharedServiceGetStructArgsClass))
#define IS_SHARED_SERVICE_GET_STRUCT_ARGS(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_ARGS))
#define IS_SHARED_SERVICE_GET_STRUCT_ARGS_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), TYPE_SHARED_SERVICE_GET_STRUCT_ARGS))
#define SHARED_SERVICE_GET_STRUCT_ARGS_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_ARGS, SharedServiceGetStructArgsClass))

/* struct SharedServiceGetStructResult */
struct _SharedServiceGetStructResult
{ 
  ThriftStruct parent; 

  /* public */
  SharedStruct * success;
  gboolean __isset_success;
};
typedef struct _SharedServiceGetStructResult SharedServiceGetStructResult;

struct _SharedServiceGetStructResultClass
{
  ThriftStructClass parent;
};
typedef struct _SharedServiceGetStructResultClass SharedServiceGetStructResultClass;

GType shared_service_get_struct_result_get_type (void);
#define TYPE_SHARED_SERVICE_GET_STRUCT_RESULT (shared_service_get_struct_result_get_type())
#define SHARED_SERVICE_GET_STRUCT_RESULT(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_RESULT, SharedServiceGetStructResult))
#define SHARED_SERVICE_GET_STRUCT_RESULT_CLASS(c) (G_TYPE_CHECK_CLASS_CAST ((c), _TYPE_SHARED_SERVICE_GET_STRUCT_RESULT, SharedServiceGetStructResultClass))
#define IS_SHARED_SERVICE_GET_STRUCT_RESULT(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_RESULT))
#define IS_SHARED_SERVICE_GET_STRUCT_RESULT_CLASS(c) (G_TYPE_CHECK_CLASS_TYPE ((c), TYPE_SHARED_SERVICE_GET_STRUCT_RESULT))
#define SHARED_SERVICE_GET_STRUCT_RESULT_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), TYPE_SHARED_SERVICE_GET_STRUCT_RESULT, SharedServiceGetStructResultClass))

#endif /* SHARED_TYPES_H */
