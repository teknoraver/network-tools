
TOOLS := breed flooz
CFLAGS = -pipe -O2 -Wall $(if $(filter breed,$@),-pthread)

all: $(TOOLS)

$(TOOLS): common.h

clean::
	rm -f $(TOOLS)
