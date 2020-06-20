CC=gcc
CFLAGS=-g -m32 -fno-omit-frame-pointer -std=c89 -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -fsanitize=address

ODIR=./src
SRCDIR=./src
IDIR=./src
CGI_DIR=./cgi-bin

LIBS=-lm

_DEPS = poolside.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = poolside.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: poolside

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ cgi-bin/poolside

poolside: $(OBJ)
	$(CC) -o $(CGI_DIR)/$@ $^ $(CFLAGS) $(LIBS)

run: poolside
	./poolcgid.py
