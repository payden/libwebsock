all:
	gcc -O2 -Wall -c sha1.c
	gcc -O2 -Wall -c base64.c
	gcc -O2 -Wall -c test.c
	gcc -O2 -Wall -c libwebsock.c
	gcc -O2 -o test libwebsock.o test.o base64.o sha1.o
clean:
	rm -f *.o
	rm -f listen
