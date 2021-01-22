# Makefile for rfc6234 code examples

LIB += lhkdf.so
DEPS = Makefile
CFLAGS += -fPIC
CFLAGS += -shared
LDFLAGS += -I/usr/include/lua5.3
# Prettifiers
LINK    = @echo "* Linking $@"; $(CC) $(CFLAGS) $(LDFLAGS)

all: ${LIB}
	@echo "* All Done"

OBJS := $(shell ls *.c | sed 's/\.c/.o/' | sed 's/ /\n/g' | sort | uniq | tr '\n' ' ')

-include $(OBJS:.o=.d)

depend: clean
	@echo "* Making dependencies for $(OBJS)"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

clean:
	@echo "* Cleansing"
	@rm -rf $(BINS) *.o *.so *.lo *.la *.slo *.loT *.d

lhkdf.so: $(DEPS) $(OBJS)
	$(LINK) -o $@ $(OBJS)

%.o: %.c $(DEPS)
	@echo "* Compiling $@";
	@$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

