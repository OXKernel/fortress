OBJS=fortress.o password.o
ALL: $(OBJS)
	g++ fortress.o password.o -o fortress
clean:
	rm -f fortress.o password.o fortress
