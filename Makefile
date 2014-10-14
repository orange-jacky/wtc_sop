CC = gcc
CFALGS = -w -g
CPP =  $(CC) -E
AR = ar
ARFALGS = -qcs
RM = rm -rf

DIR  = /home/wrt/decoder
LIB = $(DIR)/lib
BIN = $(DIR)/bin
INC = $(DIR)/inc
TEST = $(DIR)/test
VMX = $(DIR)/wtc_sop


TARGET =  libwtc_sop.so
OBJDIR = $(DIR)/objs
OBJS = $(OBJDIR)/wtc_sop.o


$(TARGET): $(OBJDIR) $(OBJS)
	$(CC) $(CFALGS) -shared -o $@  $(OBJS) -I/usr/local/include/libxml2  -I $(INC)  -lpthread -static -L$(LIB)  -lxml2

$(OBJS):$(VMX)/wtc_sop.c  
	$(CC) $(CFALGS) -fPIC -c $<  -o $@ -I $(INC) -I/usr/local/include/libxml2

$(OBJDIR):
	mkdir -p $@

clean:
	-$(RM)  $(OBJDIR)  $(TARGET)
