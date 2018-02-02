all: run dump

run: function_pointer
	./$<

function_pointer: function_pointer.c
	$(CC) -o $@ $<

dump: function_pointer
	@echo ""
	@echo "---- please compare the function binary with this result ----"
	objdump -d function_pointer | grep -A 5 --color 'function_add'

clean:
	rm -f function_pointer
