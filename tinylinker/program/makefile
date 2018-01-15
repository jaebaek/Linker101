BASE_DIR = ../../calculator

all: libcalc.so test

test: test.o
	ld -o $@ $^ -pie -emain -lc -L. -lcalc

test.o: test.c
	$(CC) -o $@ -c -fPIC $< -I$(BASE_DIR)

libcalc.so: add.o multiply.o
	ld -o $@ --shared $^

multiply.o:
	SHARED=YES make -C $(BASE_DIR) $@
	cp $(BASE_DIR)/$@ .

add.o:
	SHARED=YES make -C $(BASE_DIR) $@
	cp $(BASE_DIR)/$@ .

clean:
	rm -f *.o libcalc.so test
	make -C $(BASE_DIR) clean
