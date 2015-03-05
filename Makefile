all: BlueVirtualAP

BlueVirtualAP:	main.o
	g++ -o BlueVirtualAP main.o

main.o:	main.cpp
	g++ -c main.cpp

clean:
	rm -f *.o BlueVirtualAP
