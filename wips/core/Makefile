CC      = gcc 
CFLAGS  += -rdynamic -DMAGIC_CH=abdd
INCLUDEFLAGS += -I../include -I../../libubox -I../
LDPATH += -L../ -L../../libubox
LDFLAGS += -ldl -lwips -lubox -lglib-2.0 -lthrift-1.0.0-dev -lthriftnb-1.0.0-dev -lthriftnb -lthrift -lthriftz -lgobject-2.0 -lthrift_c_glib -lssl -lcrypto -lrt -lpthread
OBJS    =  c_glib_server.o ../gen-c_glib/calculator.o ../gen-c_glib/shared_service.o ../gen-c_glib/shared_types.o ../gen-c_glib/tutorial_types.o main.o wNode.o wipsInterface.o wipsd_parse.o time.o confread.o api.o gen-c_glib/api_types.o gen-c_glib/report_event_service.o
TARGETS = wips 

#.PHONY:all 
#all:wips
#all:$(TARGETS)

$(TARGETS):$(OBJS)
	@echo 正在编译$@
#	$(CC) $(CFLAGS) main.c $(LDPATH)  $(LDFLAGS) $(INCLUDEFLAGS) -E > tmp
	$(CC) -o $@  $(CFLAGS) $(OBJS) $(LDPATH)  $(LDFLAGS) $(INCLUDEFLAGS)

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

