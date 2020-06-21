CC=gcc
override CFLAGS += -g -m32 -fno-omit-frame-pointer -std=c89 -D_FORTIFY_SOURCE=2 -O1 -Wformat -Wformat-security -Wl,-z,relro -Wl,-z,now -fstack-protector-strong -fsanitize=address -Wno-deprecated-declarations -Wno-int-conversion

ODIR=./src
SRCDIR=./src
IDIR=./src
CGI_DIR=./cgi-bin

LIBS=-lm

all: poolside

_DEPS = poolside.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = poolside.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

_TEMPLS = body_index.templ
TEMPL = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(ODIR)/%templ: $(SRCDIR)/%.templ.html
	./to_templ.py $< $@

$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS) templates
	$(CC) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ cgi-bin/poolside $(ODIR)/*.templ

$(ODIR)/body_index.templ:
	./to_templ.py $(SRCDIR)/body_index.templ.html $(ODIR)/body_index.templ

templates: $(ODIR)/body_index.templ

poolside: $(OBJ)
	make templates
	$(CC) -o $(CGI_DIR)/$@ $^ $(CFLAGS) $(LIBS)

run: poolside
	./poolcgid.py
