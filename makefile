CC = clang

CFILES = sha1.c

STRING = ../CStringUtils

LFLAGS = -lCStringUtils -L$(STRING)
IFLAGS = -I$(STRING)

compile: $(CFILES)
	$(CC) -c $(CFILES) $(IFLAGS)
	ar -cvq libSHA1.a sha1.o 
