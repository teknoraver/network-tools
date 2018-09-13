
TOOLS := weed flooz
CFLAGS = -pipe -O2 -Wall $(if $(filter weed,$@),-pthread)

all: $(TOOLS)

$(TOOLS): common.h

clean::
	rm -f $(TOOLS)
