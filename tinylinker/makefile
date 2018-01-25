all: tinylinker example

example:
	make -C program

tinylinker: main.o tinylinker.a
	$(CC) -o $@ $^

main.o: main.c tinylinker.h
	$(CC) -o $@ -c $<

tinylinker.a: tinylinker.o
	$(AR) -rs -o $@ $^

tinylinker.o: tinylinker.c tinylinker.h elf_common.h \
	elfstructs.h tinylinker_internal.h
	$(CC) -o $@ -c $<

clean:
	make -C program clean
	rm -f *.o tinylinker.a tinylinker
