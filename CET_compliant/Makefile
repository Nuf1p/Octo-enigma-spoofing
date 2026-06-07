
all: bof 
debug: debug64

bof:
	nasm -f win64 Spoof.asm -o Spoof.o
	x86_64-w64-mingw32-gcc -Wall -DCOFF_STANDALONE beacon_compatibility.c Stomping.c COFFLoader.c Spoof.o -o COFFLoader64.exe
	x86_64-w64-mingw32-gcc -c msgbox.c -o msgbox64.o

debug64:
	nasm -f win64 Spoof.asm -o Spoof.o
	x86_64-w64-mingw32-gcc -DCOFF_STANDALONE -DDEBUG beacon_compatibility.c Stomping.c COFFLoader.c Spoof.o -o COFFLoader64.exe

nix:
	gcc -DCOFF_STANDALONE -Wall -DDEBUG beacon_compatibility.c COFFLoader.c -o COFFLoader.out

clean:
	rm -f COFFLoader64.exe COFFLoader.out
	rm -f msgbox64.o Spoof.o
