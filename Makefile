# Executable Name
NAME = famine.exe

# Tools
NASM = nasm
CL = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.42.34433\bin\Hostx64\x64\CL.exe"

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Flags
ASMFLAGS = -f win64 -w+prefix-seg  # Generate 64-bit Windows object files
CFLAGS = /c /Fo$(OBJ_DIR)\  # Compile only, no logo, specify output directory
LINKFLAGS = /Zi /link /ENTRY:start /SUBSYSTEM:CONSOLE /OUT:$(BIN_DIR)\$(NAME) /NOLOGO /NODEFAULTLIB   # Pass linker options using /link

# Source Files
ASMSRC = $(SRC_DIR)/famine.s
CSRC = $(wildcard $(SRC_DIR)/c/*.c)

# Object Files
ASMOBJS = $(patsubst $(SRC_DIR)/%.s,$(OBJ_DIR)/%.obj,$(ASMSRC))
COBJS = $(patsubst $(SRC_DIR)/c/%.c,$(OBJ_DIR)/%.obj,$(CSRC))
OBJS = $(ASMOBJS) $(COBJS)

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

$(OBJ_DIR)/%.obj: $(SRC_DIR)/c/%.c
	@echo Compiling $<
	$(CL) $(CFLAGS) $<

$(BIN_DIR)/$(NAME): $(OBJS)
	@echo Linking...
	$(CL) $(OBJS) $(LINKFLAGS)

clean:
	@if exist $(OBJ_DIR) $(DEL) $(OBJ_DIR)\*.*
	@if exist $(BIN_DIR) $(DEL) $(BIN_DIR)\*.*

re: clean all


run: re
	@echo Running...
	$(BIN_DIR)/$(NAME)

.PHONY: all clean re dirs
