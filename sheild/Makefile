
all : shield

shield : main.o
	gcc -o shield main.o -lpcap

main.o : main.c
	gcc -c -o main.o main.c -lpap

clean :
	rm *.o shield
