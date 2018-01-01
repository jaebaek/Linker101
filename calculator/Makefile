all: test

multiply.o: multiply.c multiply.h add.h
	$(CC) -c -o $@ $<

add.o: add.c add.h
	$(CC) -c -o $@ $<

clean:
	rm -f *.o libcalc.a test
