all: run

run: main
	./$<

main: add.o main.o
	$(CC) -o $@ $^

main.o: main.c
	$(CC) -o $@ -c $<

add.o: add.s
	$(CC) -o $@ -c $<

clean:
	rm -f *.o main
