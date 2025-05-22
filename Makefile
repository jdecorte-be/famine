NAME         = famine.exe

ASM          = nasm
ASM64FLAGS   = -f win64 -g

LD           = x86_64-w64-mingw32-ld

SRCDIR       = ./src/
OBJDIR       = ./obj/
PAYLOADDIR   = ./payload/

SRC          = famine.s

OBJ          = $(addprefix $(OBJDIR), $(SRC:.s=.o))

# ===== Targets =====

all: $(NAME)

$(NAME): $(OBJDIR) $(OBJ)
	$(LD) $(OBJ) -o $(NAME) -subsystem console -e main -lkernel32

clean:
	rm -rf $(NAME)

fclean: clean
	rm -rf $(OBJDIR) $(PAYLOADDIR)

re: fclean all

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)%.o: $(SRCDIR)%.s
	$(ASM) $(ASM64FLAGS) $< -o $@ 

.PHONY: all clean fclean re
