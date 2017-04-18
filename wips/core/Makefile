CC      = gcc 
CFLAGS  += -rdynamic -DMAGIC_CH=abdd
INCLUDEFLAGS += -I../include -I../../libubox
LDPATH += -L../ -L../../libubox
LDFLAGS += -ldl -lwips -lubox
OBJS    = main.o wNode.o wipsInterface.o wipsd_parse.o
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

