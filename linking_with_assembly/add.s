# .global must be added to define this symbol as "GLOBAL" symbol
# to be used in other source file.
.global function_add
function_add:
	mov %rdi, %rax
	add %rax, %rsi
	ret
