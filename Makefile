all:
	cd common; make
	cd server; make
	cd client; make

clean:
	cd common; make clean
	cd client; make clean
	cd server; make clean

