/* mtr_selftest.c — prueba unitaria de la lógica de parseo/audio del
 * driver FUSE (mtr_fuse.c). No requiere /dev/fuse.
 *
 * Se compila con -DMTR_SELFTEST (ver Makefile) e incluye mtr_fuse.c, que
 * bajo ese símbolo ejecuta el auto-test en lugar de fuse_main.
 */
#include "mtr_fuse.c"
