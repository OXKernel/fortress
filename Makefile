OBJS=fortress.o base64.o password.o
ALL: $(OBJS)
	g++ fortress.o base64.o password.o -o fortress
clean:
	rm -f fortress.o base64.o password.o fortress
