OPENCM3DIR  = libopencm3
OPENCM3NAME = opencm3_stm32f4
OPENCM3FILE = $(OPENCM3DIR)/lib/lib$(OPENCM3NAME).a
LDSCRIPT    = stm32f405x6.ld

PREFIX     ?= arm-none-eabi
CC          = $(PREFIX)-gcc
LD          = $(PREFIX)-gcc
OBJCOPY     = $(PREFIX)-objcopy
OBJDUMP     = $(PREFIX)-objdump
GDB         = $(PREFIX)-gdb

ARCH_FLAGS  = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16
DEFINES     = -DSTM32F4
OBJS        = obj/stm32f4_wrapper.o obj/keccakf1600.o
RANDOMBYTES = obj/randombytes.o

CFLAGS     += -O3 \
              -Wall -Wextra -Wimplicit-function-declaration \
              -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
              -Wundef -Wshadow \
              -I$(OPENCM3DIR)/include \
              -fno-common $(ARCH_FLAGS) -MD $(DEFINES)
LDFLAGS    += --static -Wl,--start-group -lc -lgcc -lnosys -Wl,--end-group \
              -T$(LDSCRIPT) -nostartfiles -Wl,--gc-sections \
               $(ARCH_FLAGS) -L$(OPENCM3DIR)/lib

.PHONY: clean all test speed stack 
all: test speed stack  

test:	bin/test_kyber512_m4round1.bin	bin/test_kyber512_m4round2.bin\
	bin/test_kyber768_m4round1.bin	bin/test_kyber768_m4round2.bin\
	bin/test_kyber1024_m4round1.bin	bin/test_kyber1024_m4round2.bin

speed:	bin/speed_kyber512_m4round1.bin	bin/speed_kyber512_m4round2.bin\
	bin/speed_kyber768_m4round1.bin	bin/speed_kyber768_m4round2.bin\
	bin/speed_kyber1024_m4round1.bin	bin/speed_kyber1024_m4round2.bin

stack:	bin/stack_kyber512_m4round1.bin	bin/stack_kyber512_m4round2.bin\
	bin/stack_kyber768_m4round1.bin	bin/stack_kyber768_m4round2.bin\
	bin/stack_kyber1024_m4round1.bin	bin/stack_kyber1024_m4round2.bin

obj/stack_%.o: stack.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $< \
	-Icrypto_kem/$(subst _,/,$(subst obj/stack_,,$(subst .o,,$@)))/ \
	-I./common/


elf/stack_%.elf: obj/stack_%.o $(OBJS) $(RANDOMBYTES) $(LDSCRIPT) $(OPENCM3FILE) obj/fips202.o
	make -C crypto_kem/$(subst _,/,$(subst elf/stack_,,$(subst .elf,,$@)))/ libpqm4.a
	mkdir -p elf
	$(LD) -o $@ \
	$< \
	crypto_kem/$(subst _,/,$(subst elf/stack_,,$(subst .elf,,$@)))/libpqm4.a \
	$(OBJS) obj/fips202.o $(RANDOMBYTES) $(LDFLAGS) -l$(OPENCM3NAME)

obj/test_%.o: test.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $< \
	-Icrypto_kem/$(subst _,/,$(subst obj/test_,,$(subst .o,,$@)))/ \
	-I./common/


# elf/test_%.elf: obj/test_%.o $(OBJS) $(RANDOMBYTES) $(LDSCRIPT) $(OPENCM3FILE) obj/fips202.o
.PRECIOUS: elf/test_%.elf
elf/test_%.elf: obj/test_%.o $(OBJS) $(RANDOMBYTES) $(LDSCRIPT) $(OPENCM3FILE) obj/fips202.o
	make -C crypto_kem/$(subst _,/,$(subst elf/test_,,$(subst .elf,,$@)))/ libpqm4.a
	mkdir -p elf
	$(LD) -o $@ \
	$< \
	crypto_kem/$(subst _,/,$(subst elf/test_,,$(subst .elf,,$@)))/libpqm4.a \
	$(OBJS) obj/fips202.o $(RANDOMBYTES) $(LDFLAGS) -l$(OPENCM3NAME)


obj/speed_%.o: speed.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $< \
	-Icrypto_kem/$(subst _,/,$(subst obj/speed_,,$(subst .o,,$@)))/ \
	-I./common/


elf/speed_%.elf: obj/speed_%.o $(OBJS) $(RANDOMBYTES) $(LDSCRIPT) $(OPENCM3FILE) obj/fips202.o
	make -C crypto_kem/$(subst _,/,$(subst elf/speed_,,$(subst .elf,,$@)))/ libpqm4.a
	mkdir -p elf
	$(LD) -o $@ \
	$< \
	crypto_kem/$(subst _,/,$(subst elf/speed_,,$(subst .elf,,$@)))/libpqm4.a \
	$(OBJS) obj/fips202.o $(RANDOMBYTES) $(LDFLAGS) -l$(OPENCM3NAME)

bin/%.bin: elf/%.elf
	mkdir -p bin
	$(OBJCOPY) -Obinary $^ $@

obj/randombytes.o: common/randombytes.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $^

obj/stm32f4_wrapper.o:  common/stm32f4_wrapper.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $^

obj/fips202.o:  common/fips202.c
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $^

obj/keccakf1600.o:  common/keccakf1600.S
	mkdir -p obj
	$(CC) $(CFLAGS) -o $@ -c $^
	-I./dummy/crypto_kem/

clean:
	find . -name \*.o -type f -exec rm -f {} \;
	find . -name \*.d -type f -exec rm -f {} \;
	find crypto_kem -name \*.a -type f -exec rm -f {} \;
	rm -rf elf/
	rm -rf bin/
	rm -rf obj/
