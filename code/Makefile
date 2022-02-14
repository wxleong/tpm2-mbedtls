SRC := $(wildcard *.c */*.c)
OBJ := $(patsubst %.c,%.o,$(SRC))
DEP := $(SRC:.c=.d)

$(info Sources=$(SRC))
$(info Objects=$(OBJ))

CPPFLAGS := -MMD
CC := gcc
LDFLAGS := 
LDLIBS := -ltss2-sys -ltss2-esys -ltss2-mu -ltss2-rc -ltss2-tctildr -Lmbedtls-2.28.0/ -lmbedcrypto -lmbedtls -lmbedx509
CFLAGS := -Os -std=c99 -I/usr/local/include/tss2 -Imbedtls-2.28.0/include -Itpm/ -DTCTI_NAME_CONF=\"device:/dev/tpmrm0\"

main: $(OBJ)

.PHONY: clean
clean:
	rm -f main $(OBJ) $(DEP)

-include $(DEP)
