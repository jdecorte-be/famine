NAME = famine.exe

CL = C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.41.34120\bin\HostX64\x64\CL.exe
NASM = nasm

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

CLFLAGS = /c /Zi /nologo /W4 /diagnostics:column /O1 /Os /Oy /GL /GS- /Zc:inline /FA /external:W4 /TC /Zl
LINKFLAGS = /OUT:"$(BIN_DIR)/$(NAME)" /LTCG:incremental /MACHINE:X64 /ENTRY:"Run" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /LTCGOUT:"$(BIN_DIR)/$(NAME).iobj" /MAP:"$(BIN_DIR)/$(NAME).map" /ORDER:@"src\function_link_order.txt" /OPT:ICF /ILK:"$(BIN_DIR)/$(NAME).ilk" /NOLOGO /NODEFAULTLIB 
ASMFLAGS = -f win64

SRCS = $(SRC_DIR)/woody.c 
ASMSRC = $(SRC_DIR)/asm/test.s
OBJS = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.obj,$(SRCS)) $(patsubst $(SRC_DIR)/%.s,$(OBJ_DIR)/%.obj,$(ASMSRC))

# Commands
DEL = del /Q
LINK = link

# Rules
all: dirs $(BIN_DIR)/$(NAME)

dirs:
	@if not exist $(OBJ_DIR) mkdir $(OBJ_DIR)
	@if not exist $(BIN_DIR) mkdir $(BIN_DIR)
	@if not exist "$(OBJ_DIR)/asm" mkdir "$(OBJ_DIR)/asm"

$(OBJ_DIR)/%.obj: $(SRC_DIR)/%.c
	@echo Compiling C$<
	$(CL) $(CLFLAGS) /Fo"$@" /Fa"$(BIN_DIR)/" $<

$(OBJ_DIR)/%.obj: $(SRC_DIR)/%.s
	@echo Compiling ASM$<
	$(NASM) $(ASMFLAGS) -o "$@" $<


$(OBJ_DIR)/%.obj: $(SRC_DIR)/%.s
	$(NASM) $(ASFLAGS) -o "$@" $<

$(BIN_DIR)/$(NAME): $(OBJS)
	@echo Linking...
	$(LINK) $(LINKFLAGS) $(OBJS)
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\script\Out-Shellcode.ps1 .\bin\famine.exe .\bin\famine.exe.map .\bin\famine.bin     


clean:
	@if exist $(OBJ_DIR) $(DEL) $(OBJ_DIR)\*.*

fclean: clean
	@if exist $(BIN_DIR) $(DEL) $(BIN_DIR)\*.*

re: fclean all

.PHONY: all clean fclean re dirs


#  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Out-Shellcode.ps1 ..\bin\famine.exe ..\bin\famine.exe.map ..\bin\famine.bin     
