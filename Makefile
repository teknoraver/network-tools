TOOLS := breed flooz

CFLAGS := -pipe -O2 -Wall

all: $(TOOLS)

breed: breed.c
	$(CC) $(CFLAGS) -pthread $^ -o $@

clean::
	rm -f $(TOOLS)
