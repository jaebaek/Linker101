# please call this makefile using
#    $ SHARED=YES make

ifdef SHARED
SHARED_CFLAGS = -fPIC
SHARED_LDFLAGS = --shared
endif

LDFLAGS_FOR_TEST = -L. -lcalc

all: run

run: test
	@LD_LIBRARY_PATH=. ./test

test: test.o libcalc.so
	$(CC) -o $@ $^ -L. -lcalc

libcalc.a: add.o multiply.o
	$(AR) -rs $@ $^

libcalc.so: add.o multiply.o
	$(CC) -o $@ $(SHARED_LDFLAGS) add.o multiply.o

multiply.o: multiply.c multiply.h add.h
	$(CC) -c -o $@ $(SHARED_CFLAGS) $<

add.o: add.c add.h
	$(CC) -c -o $@ $(SHARED_CFLAGS) $<

clean:
	rm -f *.o libcalc.a test
