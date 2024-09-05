NAME = pipex

CC = gcc

INCLUDES = include

CFLAGS = -Werror -Wall -Wextra -fsanitize=address

RM = rm -rf

SRCS = 	src/main.c

$(NAME) :
	gcc $(CFLAGS) $(SRCS) -I $(INCLUDES) -o $(NAME)

all : $(NAME)

fclean : clean
	$(RM) $(NAME)

clean :
	$(RM) $(NAME)

re : fclean all
