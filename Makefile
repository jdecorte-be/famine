NAME          =  famine

ASM           =  nasm
ASM64FLAGS    =  -f elf64 -g
ASM32FLAGS    =  -f elf32 -g

LD            =  ld

SRCDIR        =  ./src/
OBJDIR        =  ./obj/
PAYLOADDIR    =  ./payloads/

SRC           =  main.s \
				 famine.s \

OBJ           =  ${addprefix $(OBJDIR), $(SRC:%.s=%.o)}

PAYLOAD_SRC   =  famine.s \
				 loader.s \

PAYLOADS      =  ${addprefix $(PAYLOADDIR), $(PAYLOAD_SRC:%.s=%.bin)}


# ===== #


all:	COPY_PAYLOAD $(NAME)


COPY_PAYLOAD: $(PAYLOADDIR) $(PAYLOADS)
	python3 ./copy_payload.py


$(NAME): $(OBJDIR) $(OBJ) $(PAYLOADDIR) $(PAYLOADS)
	$(LD) $(OBJ) -o $(NAME)


clean:
	rm -rf $(NAME)


fclean:	clean
	rm -rf $(OBJDIR) $(PAYLOADDIR)


re:	fclean all


$(OBJDIR):
	@mkdir -p $(OBJDIR)


$(PAYLOADDIR):
	@mkdir -p $(PAYLOADDIR)


$(OBJDIR)%.o:	$(SRCDIR)%.s
	$(ASM) $(ASM64FLAGS) $< -o $@ 


$(PAYLOADDIR)%.bin:	$(SRCDIR)%.s
	$(ASM) -f bin $< -o $@


.PHONY:	all clean fclean re
