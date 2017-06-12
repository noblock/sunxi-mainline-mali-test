include Makefile.inc

DIRS = fixer

.PHONY: all clean install $(DIRS)

all: CMD = make all
all: $(DIRS)

$(DIRS):
	$(CMD) -C $@

install: CMD = make install
install: remount $(DIRS)

clean: CMD = make clean
clean: $(DIRS)

include Makefile.post
