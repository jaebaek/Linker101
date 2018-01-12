all: test

test: first.o second.o
	gcc -o test first.o second.o

first.o: first.c
	gcc -o first.o -c first.c

second.o: second.c
	gcc -o second.o -c second.c

clean:
	rm -f *.o test
