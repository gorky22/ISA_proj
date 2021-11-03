PROJ=secret
CC=gcc
LIBS=-lcrypto -lpcap
RM=rm -f
FILES=secret.c client.c server.c

$(PROJ) : $(FILES)
	$(CC) -o $(PROJ) $(FILES) $(LIBS)
	
clean:
	$(RM) *.o $(PROJ)