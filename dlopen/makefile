all: call_cosin

call_cosin: call_cosin.o
	gcc -o call_cosin call_cosin.o -ldl

call_cosin.o: call_cosin.c
	gcc -o call_cosin.o -c call_cosin.c

clean:
	rm -f *.o call_cosin
