TARGET=mmcsv2json.so

SOURCES=mmcsv2json.c
OBJECTS=mmcsv2json.o

LDFLAGS= -shared -fPIC
CFLAGS= -fPIC -g -O2 -Wall -Wextra

CFLAGS += -I./rsyslog/ -I./rsyslog/runtime/ -I./rsyslog/grammar/ 

CFLAGS += $(shell pkg-config --cflags libfastjson)
LDFLAGS += $(shell pkg-config --libs libfastjson)

LDFLAGS += -lcsv
	

${TARGET}: ${OBJECTS}
	${CC} ${LDFLAGS} -o $@ $^

${OBJECTS}: ${SOURCES}


clean:
	rm -rf *.o *.so

install:
	mkdir -p ${DESTDIR}/lib64/rsyslog/
	cp ${TARGET} ${DESTDIR}/lib64/rsyslog/
