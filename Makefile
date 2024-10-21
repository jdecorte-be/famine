# Executable Name
NAME = famine.exe

# Tools
NASM = nasm
CL = C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.41.34120\bin\HostX64\x64\CL.exe

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Flags
ASMFLAGS = -f win64  # Generate 64-bit Windows object files
LINKFLAGS = /Zi /link /ENTRY:start /SUBSYSTEM:CONSOLE /OUT:$(BIN_DIR)\$(NAME)  # Pass linker options using /link

# Correct Path to 64-bit Windows SDK Libraries
KERNEL32_LIB = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64\kernel32.lib"

# Source Files
ASMSRC = $(SRC_DIR)/famine.s $(SRC_DIR)/entry.s $(SRC_DIR)/utils.s $(SRC_DIR)/proc.s

# Object Files
OBJS = $(OBJ_DIR)/famine.obj $(OBJ_DIR)/entry.obj $(OBJ_DIR)/utils.obj $(OBJ_DIR)/proc.obj

# Commands
DEL = del /Q

# Rules
all: dirs $(BIN_DIR)/$(NAME)

dirs:
	@if not exist $(OBJ_DIR) mkdir $(OBJ_DIR)
	@if not exist $(BIN_DIR) mkdir $(BIN_DIR)

$(OBJ_DIR)/%.obj: $(SRC_DIR)/%.s
	@echo Assembling $<
	$(NASM) $(ASMFLAGS) $< -o $@ 

$(BIN_DIR)/$(NAME): $(OBJS)
	@echo Linking...
	$(CL) $(OBJS) $(KERNEL32_LIB) $(LINKFLAGS)

clean:
	@if exist $(OBJ_DIR) $(DEL) $(OBJ_DIR)\*.*
	@if exist $(BIN_DIR) $(DEL) $(BIN_DIR)\*.*

re: clean all

.PHONY: all clean re dirs
