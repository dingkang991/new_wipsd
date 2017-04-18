1.install json-c
 sh autegen.sh
 ./configure
 make
 make install

2.compile and libubox
 sudo apt-get install lua5.1
 suao apt-get install lua5.1-dev
 cmake .
 make
 cp lib*.so /lib

3.compile ubus
 cmake .
 make

4.compile new_wips
 make




