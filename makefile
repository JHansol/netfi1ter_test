.SUFFIXES : .cpp
 
OBJECT = nfqnl.o
SRC = nfqnl.cpp
 
CC = g++
CFLAGS = -lnetfilter_queue 

TARGET = nfqnl
 
$(TARGET) : $(OBJECT)
	@echo "------------------------------------"
	@echo [Complie] $(TARGET)
	$(CC) -o $(TARGET) $(OBJECT) $(CFLAGS)
	@echo [success] $(TARGET)
	@echo "------------------------------------"
	rm -rf $(OBJECT)
 
clean :
	rm -rf $(OBJECT) $(TARGET)

new :
	@$(MAKE) -s clean
	@$(MAKE) -s
