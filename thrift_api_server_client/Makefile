CC      = gcc
CFLAGS  += -rdynamic -DMAGIC_CH=abdd
INCLUDEFLAGS += -I../include -I../../libubox
LDPATH += -L../
LDFLAGS += -ldl -lwips -lubox -lglib-2.0 -lthrift-1.0.0-dev -lthriftnb-1.0.0-dev -lthriftnb -lthrift -lthriftz -lgobject-2.0 -lthrift_c_glib -lssl -lcrypto -lrt -lpthread
OBJS_S    = c_glib_server.o gen-c_glib/calculator.o gen-c_glib/shared_service.o gen-c_glib/shared_types.o gen-c_glib/tutorial_types.o
OBJS_C    = c_glib_client.o gen-c_glib/calculator.o gen-c_glib/shared_service.o gen-c_glib/shared_types.o gen-c_glib/tutorial_types.o
#OBJS_C    = c_glib_client.o calculator.o shared_service.o shared_types.o tutorial_types.o
TARGETS = wips 

#.PHONY:all 
#all:wips
#all:$(TARGETS)

client:$(OBJS_C)
	@echo 正在编译$@
	$(CC) -o $@  $(CFLAGS) $(OBJS_C) $(LDPATH)  $(LDFLAGS) $(INCLUDEFLAGS)

server:$(OBJS_S)
	@echo 正在编译$@
	$(CC) -o $@  $(CFLAGS) $(OBJS_S) $(LDPATH)  $(LDFLAGS) $(INCLUDEFLAGS)

%.o:%.c
	@echo 正在编译$@
	$(CC) -o $@ -c $< $(CFLAGS) $(INCLUDEFLAGS)

%.d:%.c
	@echo 正在生成依赖文$@
	@set -e; rm -f $@; $(CC) -MM $< $(INCLUDEFLAGS) > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

-include $(OBJS:.o=.d)

.PHONY:clean 
clean:
	rm -f $(TARGETS) *.o *.d *.d.*
	rm server 
	rm client

