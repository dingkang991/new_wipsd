#########################################################

SHELL = /bin/sh
srcdir = .
top_srcdir = ..
top_builddir = ..
top_vsos = ../../..
#########################################################

ifeq ($(board) , ixdp4xx)
  include ../../../rules/arm/ixdp4xx.mk
else 
  ifeq ($(board) , cavium_octeon)
    include ../../../rules/mips64/cavium_mips64.mk
  else
    ifeq ($(board) , i386-fpga)
      include ../../../rules/i386-fpga/i386-fpga.mk
    else
      include ../../../rules/i386/i386.mk
    endif
  endif
endif

#TARGETS := wipsd wstatd getwlist debug
TARGETS := wipsd
INCLUDES +=-I$(top_builddir) -I$(top_builddir)/lib -I$(top_builddir)/../../kernel/include -I../libxml2-2.6.26/include \
			-I./include -I./
           
CONFIG_HEADER = $(top_builddir)/config.h

prefix = /usr/local
sysconfdir = ${prefix}/etc

NEW_DEFS = -DHAVE_SAVE_THREAD -DPRISM2_MONITOR -DMEMORY_ENABLED -DDEBUG_WIPSD -DMEMLOG
#NEW_DEFS = -DHAVE_SAVE_THREAD -DPRISM2_MONITOR -DDEBUG_WIPSD -DMEMORY_ENABLED -DWIPSD_DEBUGOUT
#DEFS = -DHAVE_CONFIG_H -DSYSCONFDIR=\"$(sysconfdir)/\" 
include ../../../rules/pub.mk

DEPDIR = .deps
LIBS_INCLUDE = -L../../ldlib/$(ARCH)
LIBS = -lz -lpthread -lm -lsqlite3 -lzebra
#LIBS = -lm -lcrypt  -lxml2 -lzebra
depcomp = $(SHELL) $(top_srcdir)/depcompnew

target_DEPENDENCIES =
#target_DEPENDENCIES = ../lib/libzebra.a
target_LDADD =  
#target_LDADD = ../lib/libzebra.a 


#target_OBJECTS = blocking.o wipsd_wnode.o wipsd_pub.o wipsd.o wipsd_interface.o wipsd_parse.o wipsd_vty.o hash.o \
#				 obstack.o wips_lan.o checklist.o fakeap.o wipsd_hook.o buildtree.o subnet_hash.o \
#				 ring.o event_report_logger.o event_mem_log.o event_sql_log.o debug.o dobj_wgate.o wgate_hash.o \
#				 wipsd_sql.o wipsd_policy.o

target_OBJECTS = blocking.o wipsd_wnode.o wipsd_pub.o wipsd.o wipsd_interface.o wipsd_parse.o wipsd_vty.o hash.o \
				 obstack.o wips_lan.o checklist.o fakeap.o wipsd_hook.o buildtree.o subnet_hash.o \
				 ring.o event_report_logger.o event_mem_log.o debug.o dobj_wgate.o wgate_hash.o \
				 wipsd_sql.o wipsd_policy.o


#COMPILE = gcc $(DEFS) $(INCLUDES)
COMPILE = $(CC) $(CFLAGS) $(DEFS) $(NEW_DEFS) $(INCLUDES) 
LINK = $(COMPILE) -o $@

.SUFFIXES:
.SUFFIXES: .c .o 

all: $(TARGETS)

ifeq ($(board), cavium_octeon)
sym_tmp = .tmp2.o

.tmp1: $(target_OBJECTS)
	$(LINK) $(target_OBJECTS) $(LIBS_INCLUDE) $(LIBS) 

.tmp1.S: .tmp1
	$(NM) -n .tmp1 > .tmp1_symbol
	$(LINUX_SYM) .tmp1_symbol .tmp1.S

.tmp1.o: .tmp1.S
	$(COMPILE) -MD -c -o .tmp1.o .tmp1.S

.tmp2: $(target_OBJECTS) .tmp1.o
	$(LINK) $(target_OBJECTS) $(LIBS_INCLUDE) $(LIBS) .tmp1.o

.tmp2.S: .tmp2
	$(NM) -n .tmp2 > .tmp2_symbol
	$(LINUX_SYM) .tmp2_symbol .tmp2.S

.tmp2.o: .tmp2.S
	$(COMPILE) -MD -c -o .tmp2.o .tmp2.S
endif

wipsd: $(target_OBJECTS) $(target_DEPENDENCIES) $(sym_tmp)
	@rm -f wipd
	$(LINK) $(target_OBJECTS) $(target_LDADD) $(LIBS_INCLUDE) $(LIBS) $(sym_tmp)

#wstatd:
#	$(CC) -D MIPS -o wstatd wstatd.c wipsd_wnode.h debug.o $(INCLUDES) -lm -lsqlite3

#getwlist:
#	$(CC) -D MIPS -o getwlist GetWList.c wipsd_wnode.h

#debug:
#	$(CC) -D MIPS -DDEBUG_HOOK_TOOL -o debug debug.c debug.h
	
-include $(DEPDIR)/deps.Po


.c.o:
	source='$<' object='$(@F)' libtool=no depdir='$(DEPDIR)'\
	depfile='$(DEPDIR)/$(*F).Po'  tmpdepfile='$(DEPDIR)/$(*F).TPo' \
	$(CCDEPMODE) $(depcomp) \
	$(COMPILE) -c `test -f '$<' || echo '$(srcdir)/'`$<
CCDEPMODE = depmode=gcc3

clean:
	-rm -f *.a *.o core *.core *~ *.Po
	-rm -f .tmp*
	-rm -f $(TARGETS)
	-rm -Rf $(DEPDIR)


.PHONY: all clean
