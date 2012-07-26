all:
	gcc -O2 -g -Wall -c sha1.c
	gcc -O2 -g -Wall -c base64.c
	gcc -O2 -g -Wall -c test.c
	gcc -O2 -g -Wall -c libwebsock.c
	gcc -O2 -g -o test libwebsock.o test.o base64.o sha1.o
clean:
	rm -f *.o
	rm -f listen
