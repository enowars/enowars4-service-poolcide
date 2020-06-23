CC=gcc
override CFLAGS += -g -m32 -fno-omit-frame-pointer -std=c89 -D_FORTIFY_SOURCE=2 -O1 -w -Wformat -Wno-implicit-function-declaration -Wno-format-security -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -fsanitize=address -Wno-deprecated-declarations -Wno-int-conversion

ODIR=./src
TDIR=./templates
SRCDIR=./src
IDIR=./src
CGI_DIR=./cgi-bin

LIBS=-lm

all: poolcide

$(TDIR)/%.templ: $(TDIR)/%.templ.html
	./to_templ.py $<

$(ODIR)/%.o: $(SRCDIR)/%.c templates
	$(CC) -c -o $@ $< $(CFLAGS) -I$(TDIR)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ cgi-bin/poolcide $(TDIR)/*.templ

templates: $(TDIR)/body_index.templ $(TDIR)/head.templ

poolcide: $(ODIR)/poolcide.o
	$(CC) -o $(CGI_DIR)/$@ $^ $(CFLAGS) $(LIBS)

run: poolcide
	./poolcgid.py
