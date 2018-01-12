echo_hello0: echo_hello1
	echo "hello"

echo_hello1: echo_hello2
	echo "hello"

echo_hello2: hello
	echo "hello"
