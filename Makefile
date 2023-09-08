# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: amaindro <marvin@42.fr>                    +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2018/05/31 14:50:34 by amaindro          #+#    #+#              #
#    Updated: 2018/05/31 15:05:26 by amaindro         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

NAME = Death

SRC = main.c tools.c

OBJ = $(SRC:.c=.o)

LIB = -L libft/ -lft

MAKELIB = make -C ./libft

CLEANLIB = make clean -C ./libft

FCLEANLIB = make fclean -C ./libft

all : $(NAME)

test :
	@cp /bin/ls test/
	@gcc test/sample.c -o test/sample
	@rm -rf /tmp/test0
	@cp -r test0 /tmp
	@rm -rf /tmp/test
	@cp -r test /tmp
	@rm -rf /tmp/test2
	@cp -r /tmp/test /tmp/test2
	
$(NAME) : $(OBJ) test antidisa
	$(MAKELIB)
	@gcc -s -c $(SRC)
	@gcc -o $(NAME) $(OBJ) $(LIB)
	@./anti_disassembly $(NAME)
	@./$(NAME)
	@rm $(NAME)
	@mv /tmp/test0/child $(NAME)

antidisa :
	@gcc anti_disassembly.c -o anti_disassembly

clean :
	$(CLEANLIB)
	@rm -rf $(OBJ)

fclean : clean
	$(FCLEANLIB)
	@rm -rf $(NAME)

re : fclean all

.PHONY: all test clean fclean re

