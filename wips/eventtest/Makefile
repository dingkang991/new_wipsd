CFLAGS  += -fPIC -shared -Dmagic_ch=124
INCLUDEFLAGS += -I../include
LDPATH += -L../
LDFLAGS += -lwips
OBJS    = eventtest.o 
TARGETS = libtest.so
SOURCES = $(OBJS:.o=.c)

#.PHONY:all 
#all:wips
#all:$(TARGETS)

$(TARGETS):$(OBJS)
	@echo 正在编译$@
	$(CC) -o $@ $(CFLAGS) $(LDPATH) $(LDFLAGS) $(INCLUDEFLAGS) $(SOURCES)

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

