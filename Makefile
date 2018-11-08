.DEFAULT_GOAL = all
.PHONY: all clean

programs = 84

OPTIM = 0

Q = @
E = @ echo

-include local.make

all: 84_stable $(programs)

clean:
	$(E) CLEAN
	$(Q) rm -f *.o *.c.d 84_stable $(programs) $(programs:%=%.c)

support.o: support.c
	$(E) "CC  $@"
	$(Q) $(CC) -std=gnu11 -static -fno-stack-protector -O2 -I. -c $< -Wall

$(programs): %: %.c

$(programs:%=%.c): 84_stable
	$(E) "84  $@"
	$(Q) ./84_stable $(@:%.c=%)

$(programs) 84_stable: support.o
	$(E) "CC  $@"
	$(Q) $(CC) -std=gnu11 -static -s -fno-stack-protector -nostdlib -Wl,--build-id=none \
		-O$(OPTIM) -I. -o $@ $@.c support.o \
		-Wno-unused-variable -Wno-unused-function -Wno-unused-value

84_stable: 84_stable.c

-include *.c.d
