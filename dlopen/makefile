all: run

run: call_libcalc
	@./call_libcalc

call_libcalc: call_libcalc.o
	gcc -o call_libcalc call_libcalc.o -ldl

call_libcalc.o: call_libcalc.c
	gcc -o call_libcalc.o -c call_libcalc.c

clean:
	rm -f *.o call_libcalc
