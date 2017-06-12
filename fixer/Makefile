include ../Makefile.inc

TOP=..

CFLAGS += -I$(TOP)/include -fPIC

OBJS = fixer.o

all: libMali_fixer.so

clean:
	rm -f *.P
	rm -f *.o
	rm -f *.so

libMali_fixer.so: $(OBJS)
	$(CC) -shared -o $@ $^ -ldl

install: libMali_fixer.so
	$(INSTALL) libMali_fixer.so $(prefix)/lib/

include ../Makefile.post
