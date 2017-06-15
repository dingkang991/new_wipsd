CFLAGS := -Wall -O -w -g 
#CFLAGS += -DLOG_INFO
export CFLAGS
default: lib wips libtest libtest2
.PHONY:default
.PHONY:lib
.PHONY:wips
.PHONY:libtest
.PHONY:libtest2
.PHONY:clean

lib:
	make -C lib
	sudo cp lib/libwips.so /lib
	sudo cp lib/libwips.so .
wips:
	thrift -r --gen c_glib tutorial.thrift
	cp gen-c_glib/ core/gen-c_glib_server/ -rf 
	make -C core
	cp core/wips .

libtest:
	make -C eventtest 
	cp eventtest/libtest.so .

libtest2:
	make -C eventtest2
	cp eventtest2/libtest2.so .

clean:
	make clean -C ./core
	make clean -C eventtest
	make clean -C eventtest2
	make clean -C lib
	$(RM) wips *.so
