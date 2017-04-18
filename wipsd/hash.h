/* hash.h -- header file for gas hash table routines
   Copyright 1987, 1992, 1993, 1995, 1999, 2003, 2005, 2007, 2008
   Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef HASH_H
#define HASH_H

/* Includes */
//#include "config.h"

//#ifdef STDC_HEADERS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
//#else
//#error This program requires the ANSI C Headers
//#endif

#include <sys/types.h>

/* Integer types */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#else
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#endif

#ifdef __CYGWIN__
#include <windows.h>	/* Include windows.h if compiling under Cygwin */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
/* Include getopt.h for the sake of getopt_long.
   We don't need the declaration of getopt, and it could conflict
   with something from a system header file, so effectively nullify that.  */
#define getopt getopt_loser
#include "getopt.h"
#undef getopt
#endif

#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_REGEX_H
#include <regex.h>		/* Posix regular expression functions */
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_PCAP_H
/*
 * The pcap.h header file on Apple Mac OS Xcode 2.5 and later includes pcap's
 * cut-down version of bpf.h, which defines macros that conflict with those in
 * the full bpf.h. To avoid the conflict, we include net/bpf.h before pcap.h
 * if compiling under Xcode 2.5 or later. This defines all the required macros
 * and prevents pcap's cut-down version from defining its own ones.
 *
 * 5370 is the value of __APPLE_CC__ for Xcode 2.5 on Tiger with GCC 4.0.1
 */
#if defined(__APPLE_CC__) && (__APPLE_CC__ >= 5370)
#include <net/bpf.h>
#endif
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef ARP_PCAP_DLPI
#ifdef HAVE_SYS_BUFMOD_H
#include <sys/bufmod.h>
#endif
#endif


struct hash_control;

/* Set the size of the hash table used.  */

void set_gas_hash_table_size (unsigned long);

/* Create a hash table.  This return a control block.  */

extern struct hash_control *hash_new (void);
extern struct hash_control *hash_new_bysize (unsigned long new_size);

/* Delete a hash table, freeing all allocated memory.  */

extern void hash_die (struct hash_control *);

/* Insert an entry into a hash table.  This returns NULL on success.
   On error, it returns a printable string indicating the error.  It
   is considered to be an error if the entry already exists in the
   hash table.  */

extern const char *hash_insert (struct hash_control *,
				const char *key, int key_len, void *value);

/* Insert or replace an entry in a hash table.  This returns NULL on
   success.  On error, it returns a printable string indicating the
   error.  If an entry already exists, its value is replaced.  */

extern const char *hash_jam (struct hash_control *,
			     const char *key, void *value);

/* Replace an existing entry in a hash table.  This returns the old
   value stored for the entry.  If the entry is not found in the hash
   table, this does nothing and returns NULL.  */

extern void *hash_replace (struct hash_control *, const char *key,
			 void *value);

/* Find an entry in a hash table, returning its value.  Returns NULL
   if the entry is not found.  */

extern void *hash_find (struct hash_control *, const char *key, int key_len);

/* As hash_find, but KEY is of length LEN and is not guaranteed to be
   NUL-terminated.  */

extern void *hash_find_n (struct hash_control *, const char *key, size_t len);

/* Delete an entry from a hash table.  This returns the value stored
   for that entry, or NULL if there is no such entry.  */

extern void *hash_delete (struct hash_control *, const char *key, int key_len, int);

/* Traverse a hash table.  Call the function on every entry in the
   hash table.  */

extern void hash_traverse (struct hash_control *,
			   void (*pfn) (const char *key, void *value));

/* Print hash table statistics on the specified file.  NAME is the
   name of the hash table, used for printing a header.  */

extern void hash_print_statistics (FILE *, const char *name,
				   struct hash_control *);

#endif /* HASH_H */
