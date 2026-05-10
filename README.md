# senandika
<code>write(1, msg)</code> lalu <code>exit(0)</code> generator shellcode.

Cara pake:

<pre>
febri@ubuntu:~/senandika$ make asm-nl MSG=febnug KEY=0x22
printf '%b' 'febnug\n' > examples/out.msg
python3 senandika.py --file examples/out.msg --key 0x22 --asm examples/out.asm --format hex > examples/out.hex

[+] len: 41
[+] msg_len: 7
[+] xor_key: 0x22
[+] badchars: clean
nasm -f elf64 examples/out.asm -o examples/out.o
ld examples/out.o -o examples/out
./examples/out
febnug
febri@ubuntu:~/senandika$ make dump-hex MSG=febnug KEY=0x22
python3 senandika.py "febnug" --key 0x22 --asm examples/out.asm --format hex > examples/out.hex

[+] len: 40
[+] msg_len: 6
[+] xor_key: 0x22
[+] badchars: clean
nasm -f elf64 examples/out.asm -o examples/out.o
ld examples/out.o -o examples/out
objcopy -O binary -j .text examples/out.o examples/out.bin
xxd -p examples/out.bin | tr -d '\n' | sed 's/../\\x&/g'
\xeb\x2c\x5e\x48\x83\xec\x0e\x48\x89\xe7\x31\xc9\xb1\x06\xac\x34\x22\xaa\xe2\xfa\x31\xc0\xb0\x01\x31\xff\x40\xb7\x01\x48\x89\xe6\x31\xd2\xb2\x06\x0f\x05\x31\xc0\xb0\x3c\x31\xff\x0f\x05\xe8\xcf\xff\xff\xff\x44\x47\x40\x4c\x57\x45
febri@ubuntu:~/senandika$
</pre>
