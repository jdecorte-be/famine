NAME = injection.exe
FAMINE = famine.exe

CC = gcc
AS = nasm
INCLUDES = include
CFLAGS = -g #-Werror -Wall -Wextra #-fsanitize=address
ASFLAGS = -f win64 -g
DEL = del /Q
SRCS = src\main.c src\woody.c
ASMSRC = famine.s
OBJS = $(SRCS:.c=.o)
ASMOBJ = $(ASMSRC:.s=.obj)

# Rule to generate object files from C source files
%.o: %.c
	$(CC) $(CFLAGS) -I $(INCLUDES) -c $< -o $@

# Rule to generate object files from assembly source files
%.obj: %.s
	$(AS) $(ASFLAGS) $< -o $@

# Main target to link the injection executable
$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -I $(INCLUDES) -o $(NAME)

# Target to link the famine executable
$(FAMINE): $(ASMOBJ)
	$(CC) $(CFLAGS) $(ASMOBJ) -o $(FAMINE)

all: $(NAME) $(FAMINE)

# Clean object files and executables
clean:
	$(DEL) $(OBJS) $(ASMOBJ)

fclean: clean
	$(DEL) $(NAME) $(FAMINE)

# Rebuild everything
re: fclean all

# Declare these targets as phony to avoid filename conflicts
.PHONY: all clean fclean re