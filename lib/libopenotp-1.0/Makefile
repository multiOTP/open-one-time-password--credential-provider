VERSION=1.0.7
CC=gcc
CFLAGS=-fPIC -I. -I/usr/include/libxml2 \
       -DHAVE_SSL -DHAVE_PTHREAD_H -DHAVE_SIGNAL_H -DHAVE_ERRNO_H \
       -DHAVE_STRING_H -DHAVE_STDIO_H -DHAVE_STDLIB_H -DHAVE_STDARG_H \
       -DHAVE_SYS_TYPES_H -DHAVE_SYS_SOCKET_H -DHAVE_SYS_SELECT_H \
       -DHAVE_NETINET_IN_H -DHAVE_ARPA_INET_H -DHAVE_NETDB_H \
       -DHAVE_TIME_H -DHAVE_FCNTL_H -DHAVE_UNISTD_H \
       -DHAVE_OPENSSL_RAND_H -DHAVE_OPENSSL_ERR_H
LDFLAGS=-L.

all: libopenotp.a libopenotp.so

openotp.o: openotp.h openotp.c 
	$(CC) $(CFLAGS) -c openotp.c

opensso.o: opensso.h opensso.c
	$(CC) $(CFLAGS) -c opensso.c

tiqr.o: tiqr.h tiqr.c
	$(CC) $(CFLAGS) -c tiqr.c

encode.o: encode.h encode.c 
	$(CC) $(CFLAGS) -c encode.c

ssllock.o: ssllock.h ssllock.c 
	$(CC) $(CFLAGS) -c ssllock.c

soap-client.o: libcsoap/soap-client.h libcsoap/soap-client.c 
	$(CC) $(CFLAGS) -c libcsoap/soap-client.c -o libcsoap/soap-client.o

soap-ctx.o: libcsoap/soap-ctx.h libcsoap/soap-ctx.c 
	$(CC) $(CFLAGS) -c libcsoap/soap-ctx.c -o libcsoap/soap-ctx.o

soap-env.o: libcsoap/soap-env.h libcsoap/soap-env.c 
	$(CC) $(CFLAGS) -c libcsoap/soap-env.c -o libcsoap/soap-env.o

soap-fault.o: libcsoap/soap-fault.h libcsoap/soap-fault.c 
	$(CC) $(CFLAGS) -c libcsoap/soap-fault.c -o libcsoap/soap-fault.o

soap-xml.o: libcsoap/soap-xml.h libcsoap/soap-xml.c 
	$(CC) $(CFLAGS) -c libcsoap/soap-xml.c -o libcsoap/soap-xml.o

nanohttp-client.o: nanohttp/nanohttp-client.h nanohttp/nanohttp-client.c 
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-client.c -o nanohttp/nanohttp-client.o

nanohttp-common.o: nanohttp/nanohttp-common.h nanohttp/nanohttp-common.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-common.c -o nanohttp/nanohttp-common.o

nanohttp-logging.o: nanohttp/nanohttp-logging.h nanohttp/nanohttp-logging.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-logging.c -o nanohttp/nanohttp-logging.o

nanohttp-mime.o: nanohttp/nanohttp-mime.h nanohttp/nanohttp-mime.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-mime.c -o nanohttp/nanohttp-mime.o

nanohttp-request.o: nanohttp/nanohttp-request.h nanohttp/nanohttp-request.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-request.c -o nanohttp/nanohttp-request.o

nanohttp-response.o: nanohttp/nanohttp-response.h nanohttp/nanohttp-response.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-response.c -o nanohttp/nanohttp-response.o

nanohttp-server.o: nanohttp/nanohttp-server.h nanohttp/nanohttp-server.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-server.c -o nanohttp/nanohttp-server.o

nanohttp-socket.o: nanohttp/nanohttp-socket.h nanohttp/nanohttp-socket.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-socket.c -o nanohttp/nanohttp-socket.o

nanohttp-ssl.o: nanohttp/nanohttp-ssl.h nanohttp/nanohttp-ssl.c 
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-ssl.c -o nanohttp/nanohttp-ssl.o

nanohttp-stream.o: nanohttp/nanohttp-stream.h nanohttp/nanohttp-stream.c
	$(CC) $(CFLAGS) -c nanohttp/nanohttp-stream.c -o nanohttp/nanohttp-stream.o

libopenotp.a: openotp.o opensso.o tiqr.o encode.o ssllock.o \
	libcsoap/soap-client.o libcsoap/soap-ctx.o libcsoap/soap-env.o libcsoap/soap-fault.o libcsoap/soap-xml.o \
	nanohttp/nanohttp-client.o nanohttp/nanohttp-ssl.o nanohttp/nanohttp-socket.o nanohttp/nanohttp-common.o \
	nanohttp/nanohttp-response.o nanohttp/nanohttp-stream.o nanohttp/nanohttp-server.o nanohttp/nanohttp-request.o \
	nanohttp/nanohttp-logging.o nanohttp/nanohttp-mime.o
	ar rc libopenotp.a openotp.o opensso.o tiqr.o encode.o ssllock.o libcsoap/soap-*.o nanohttp/nanohttp-*.o

libopenotp.so: libopenotp.a
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,libopenotp.so.1 -o libopenotp.so.$(VERSION) \
	openotp.o opensso.o tiqr.o encode.o ssllock.o libcsoap/soap-*.o nanohttp/nanohttp-*.o \
	-lpthread -ldl -lm -lxml2 -lssl -lcrypto
	rm -f libopenotp.so.1 libopenotp.so
	ln -s libopenotp.so.$(VERSION) libopenotp.so.1
	ln -s libopenotp.so.$(VERSION) libopenotp.so

testclients: libopenotp.so examples/openotp_login.c examples/openotp_status.c \
	     examples/opensso_start.c examples/opensso_stop.c examples/opensso_check.c examples/opensso_status.c \
	     examples/tiqr_start.c examples/tiqr_check.c examples/tiqr_cancel.c examples/tiqr_sessionqr.c examples/tiqr_status.c
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/openotp_login.c -o examples/openotp_login
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/openotp_status.c -o examples/openotp_status
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/opensso_start.c -o examples/opensso_start
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/opensso_stop.c -o examples/opensso_stop
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/opensso_check.c -o examples/opensso_check
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/opensso_status.c -o examples/opensso_status
	$(CC) $(CFLAGS) $(LDFLAGS) -ldl -lopenotp examples/tiqr_start.c -o examples/tiqr_start
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/tiqr_check.c -o examples/tiqr_check
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/tiqr_cancel.c -o examples/tiqr_cancel
	$(CC) $(CFLAGS) $(LDFLAGS) -ldl -lopenotp examples/tiqr_sessionqr.c -o examples/tiqr_sessionqr
	$(CC) $(CFLAGS) $(LDFLAGS) -lopenotp examples/tiqr_status.c -o examples/tiqr_status

install:
	[ -d /usr/lib64 ] && rm -f /usr/lib64/libopenotp.* || rm -f /usr/lib/libopenotp.*
	[ -d /usr/lib64 ] && cp -a libopenotp.so* libopenotp.a /usr/lib64 || cp -a libopenotp.so* libopenotp.a /usr/lib
	cp openotp.h opensso.h tiqr.h /usr/include
	ldconfig

clean:
	rm -f *.o *.a *.so *.so.*
	rm -f libcsoap/*.o
	rm -f nanohttp/*.o
	rm -f examples/openotp_login examples/openotp_status
	rm -f examples/opensso_start examples/opensso_stop examples/opensso_check examples/opensso_status
	rm -f examples/tiqr_start examples/tiqr_check examples/tiqr_cancel examples/tiqr_sessionqr examples/tiqr_status
