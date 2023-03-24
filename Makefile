bruteforce: bruteforce.c
	gcc -o bruteforce -lz -lcrypto -O3 -Wall bruteforce.c

clean:
	rm bruteforce
