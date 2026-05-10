PY      ?= python3
NASM    ?= nasm
LD      ?= ld
OBJCOPY ?= objcopy

MSG     ?= FN
KEY     ?= 0x11
OUTDIR  ?= examples
OUT     ?= $(OUTDIR)/out
RAW     ?= $(OUT).bin

.PHONY: all build asm asm-nl run dump dump-hex dump-c clean

all: asm

build:
	$(PY) senandika.py "$(MSG)" --key $(KEY) --asm $(OUT).asm --format hex > $(OUT).hex
	$(NASM) -f elf64 $(OUT).asm -o $(OUT).o
	$(LD) $(OUT).o -o $(OUT)

asm: build
	./$(OUT)

asm-nl:
	printf '%b' '$(MSG)\n' > $(OUT).msg
	$(PY) senandika.py --file $(OUT).msg --key $(KEY) --asm $(OUT).asm --format hex > $(OUT).hex
	$(NASM) -f elf64 $(OUT).asm -o $(OUT).o
	$(LD) $(OUT).o -o $(OUT)
	./$(OUT)

run:
	./$(OUT)

dump: build
	$(OBJCOPY) -O binary -j .text $(OUT).o $(RAW)
	xxd -i $(RAW)
	@echo
	@wc -c $(RAW)

dump-hex: build
	$(OBJCOPY) -O binary -j .text $(OUT).o $(RAW)
	xxd -p $(RAW) | tr -d '\n' | sed 's/../\\x&/g'
	@echo

dump-c: build
	$(OBJCOPY) -O binary -j .text $(OUT).o $(RAW)
	@printf 'unsigned char sc[] =\n"'
	@xxd -p $(RAW) | tr -d '\n' | sed 's/../\\x&/g'
	@printf '";\n'
	@printf 'unsigned int sc_len = %s;\n' "$$(wc -c < $(RAW))"

clean:
	rm -f $(OUT) $(OUT).o $(OUT).asm $(OUT).hex $(OUT).bin $(OUT).msg
