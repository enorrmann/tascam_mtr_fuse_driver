# Makefile — driver FUSE de solo lectura para la partición MTR (TASCAM)
#
# Dependencia: libfuse3 (runtime + headers). Si solo hay libfuse3.so en el
# sistema pero no los headers de desarrollo (librería binaria presente,
# no el paquete -dev), los headers en ./include proporcionan la API pública
# y ./include/libfuse_config.h suple el archivo de configuración generado.
#
# Compilación:        make            -> ./mtrfuse
# Selftest (sin fuse):make selftest   -> ./mtr_selftest
# Limpiar:            make clean

CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=31
CPPFLAGS  = -Iinclude
LDLIBS    = -lfuse3 -pthread

TARGET    := mtrfuse
SELFTEST  := mtr_selftest
SRC       := mtr_fuse.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(LDLIBS)

selftest: $(SELFTEST)

$(SELFTEST): $(SRC) mtr_selftest.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -DMTR_SELFTEST -o $@ mtr_selftest.c $(LDLIBS)

clean:
	rm -f $(TARGET) $(SELFTEST) /tmp/audio00.wav

.PHONY: all selftest clean
