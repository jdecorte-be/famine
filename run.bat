

@echo off

set arg1=%1


nasm -f win64 "%arg1%.asm"