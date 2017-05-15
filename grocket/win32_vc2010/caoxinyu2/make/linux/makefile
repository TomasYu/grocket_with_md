# caoxinyu for Linux

CC          = gcc
CPPC        = g++
INCLUDE     = -I../../third_party/grocket -I../../third_party/fclass/include -I../../include
LIB         = -L/usr/lib -lpthread
#CFLAGS      = -fPIC -O3 -D_FILE_OFFSET_BITS=64
CFLAGS      = -fPIC -g -D_FILE_OFFSET_BITS=64

# If you use fclass library on Linux, just uncomment FCLASS_LIB
FCLASS_SO_DIR= ../../third_party/fclass/linux
#FCLASS_LIB  = -L$(FCLASS_SO_DIR) -lbase
FCLASS_LIB  =

./o/module_%.o: ../../module/%.cpp
	$(CPPC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

MODULE_OBJECTS=  \
	./o/module_application.o 	\
	./o/module_framework.o 		\
	./o/module_tcp_conn.o

all: $(MODULE_OBJECTS)

	$(CPPC) -shared $(LIB) $(MODULE_OBJECTS)		\
			$(FCLASS_LIB)						\
			-o ./libcaoxinyu_module.so

	cp ../../module/caoxinyu_svr.ini ./
	cp ../../third_party/grocket/linux/libbase.so ./
	cp ../../third_party/grocket/linux/grocketd ./caoxinyu_svr
	chmod a+x ./caoxinyu_svr

clean:
	rm -fr $(MODULE_OBJECTS)
	rm -fr ./libcaoxinyu_module.so
	rm -fr ./libbase.so
	rm -fr ./caoxinyu_svr
	rm -fr ./caoxinyu_svr.ini

