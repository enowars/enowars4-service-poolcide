CC=gcc
override CFLAGS += -g -m32 -fno-omit-frame-pointer -std=c89 -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -fsanitize=address -Wno-deprecated-declarations -Wno-int-conversion

ODIR=./build
TDIR=./templates
SRCDIR=./src
IDIR=./src
CGI_DIR=./cgi-bin

LIBS=-lm

all: poolside

$(TDIR)/%.templ: $(TDIR)/%.templ.html
	./to_templ.py $< $@

$(ODIR)/%.o: $(SRCDIR)/%.c
	make templates
	$(CC) -c -o $@ $< $(CFLAGS) -I$(TDIR)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ cgi-bin/poolside $(TDIR)/*.templ

templates: $(TDIR)/*.templ

poolside: $(ODIR)/*.o
	$(CC) -o $(CGI_DIR)/$@ $^ $(CFLAGS) $(LIBS)

run: poolside
	./poolcgid.py
