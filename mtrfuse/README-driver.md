# mtrfuse — Driver FUSE de solo lectura para la partición MTR (TASCAM)

`mtrfuse` monta la partición **MTR** (propietaria de TASCAM) de una tarjeta
SD / imagen de disco en modo **solo lectura**, tal y como se documenta en
`../finds.txt`. Funciona sobre las grabaciones multicanal del
DP-008EX (estéreo/tratado como L==R) y expone:

```
/                      raíz
/info.txt              información parseada (superbloque + canciones)
/SONG001/ … /SONG250/  un subdirectorio por canción "usada"
    /metadata/         bloques crudos MTR_FILE / MIS_FILE / CONT / TNOC
    /tracks/track_N.wav todos las pistas decodificadas
/wav/ y /raw/          reservados y vacíos: el driver no publica WAVs deducidos
                       heurísticamente; cada `track_N.wav` procede de un mapa
                       CONT validado.
```

El audio de las pistas del DP-008EX se guarda como **PCM 16-bit LE @44.1 kHz
con cada muestra duplicada** (L==R / mono doblado). El driver aplica de-dup
automáticamente al leer, de modo que los `.wav` que expone son PCM mono real,
reproducibles con cualquier reproductor.

---

## Compilación

Depende de **libfuse3** (runtime + headers). El Makefile compila contra la
biblioteca del sistema y los headers Apache/LGPL de libfuse que se incluyen
en `./include` (extraídos de libfuse-3.14.0 y con `libfuse_config.h` generado
a mano; útil si solo está instalada la biblioteca binaria y no el paquete
`libfuse3-dev`).

```sh
make            # -> ./mtrfuse
# alternativamente, y sin FUSE:
make selftest   # -> ./mtr_selftest (valida parseo + de-dup sin /dev/fuse)
```

Si tu sistema tiene `libfuse3-dev` instalado, puedes compilar igualmente:
```sh
gcc -O2 -D_FILE_OFFSET_BITS=64 -DFUSE_USE_VERSION=31 mtr_fuse.c -lfuse3 -pthread -o mtrfuse
```

---

## Uso

```sh
# autodetección de la partición MTR (tras la FAT32 del MBR):
./mtrfuse -i sdb.img /mnt/mtr

# especificar manualmente offset y tamaño de la partición MTR:
./mtrfuse -i sdb.img -p 4293596160 -s 26979134464 /mnt/mtr

# foreground (para depurar / no daemonizar):
./mtrfuse -i sdb.img -f /mnt/mtr

# permitir que otros usuarios locales lean el montaje:
# (requiere `user_allow_other` en /etc/fuse.conf)
./mtrfuse -i /dev/sdb -a /mnt/mtr

# desmontar cuando termine:
fusermount3 -u /mnt/mtr
```

En el entorno donde se compiló no hay `/dev/fuse` (contenedor sin privilegios),
por lo que **el montaje real no se pudo validar aquí**; en su lugar se ejecutó
`make selftest`, que valida la totalidad de la lógica de bajo nivel
(superbloque, tabla de canciones, detección y de-dup de audio).

---

## Salida del selftest (verificada)

```
mtrfuse: base=4293596160 size=26974940160 nsongs=3 raw=16
[SELFTEST] superbloque detectado OK (01 01 ...)
[SELFTEST] nsongs=3 (esperado 3: SONG001,SONG002,SONG003)
[SELFTEST] tabla de canciones OK
[SELFTEST] OK: mapa fragmentado y hueco logico
[SELFTEST] OK — lógica del driver validada
```
(Ejecutado contra `data.img`, la imagen con 3 canciones de fixture — ver
`../findings.txt` §12.)

El driver expone cada sample MONO importado en la MTR como PCM 16-bit LE de un
canal SIN duplicar (descubierto con las fixtures loop1/2/3; ver findings §12),
no como el flujo L==R doblado de la canción maestra demo.
El WAV decodificado puede validarse externamente con `sox`.

---

## Notas técnicas

- **Base de la partición MTR**: se autodetecta como `(start_LBA + n_sectores) × 512`
  del MBR (fin de la FAT32). Para esta imagen: `4293596160` bytes
  (`0x1000...`). OJO: los offsets "relativos" anotados en `../finds.txt` en el
  borrador inicial usaban un base distinto por  `0x180000`; los correctos son
  los que usa el driver (superbloque en rel `0x210000`, tabla de canciones en
  rel `0x228030`, directorio MTR en rel `0x240000`).
- **Búsqueda por firma y estructura**: el driver localiza el superbloque por
  su firma y la tabla de canciones por el marcador `SONG001`. Después valida
  cada cabecera `CONT` y busca metadata al inicio de cada unidad MTR de 2 GiB;
  por tanto no presupone que todas las canciones estén en los primeros 48 MiB.
- **Bloques fragmentados**: usa el `sample_offset` de cada entrada CONT para
  resolver la posición lógica de los samples. No asume que los bloques físicos
  sean contiguos ni que estén ordenados.
- **Dispositivos directos**: para `/dev/sdX` obtiene el tamaño con
  `BLKGETSIZE64`; no usa el `st_size` nulo típico de un dispositivo de bloques.
- **Sin falsos WAV**: se eliminó el escáner heurístico de audio crudo que podía
  confundir metadata con PCM y publicar archivos corruptos.
- **Solo lectura**: el descriptor de la imagen se abre con `O_RDONLY`. No se
  modifica ningún byte.
- **Montaje sin root**: ejecuta el driver como tu usuario cuando éste tenga
  permiso de lectura sobre el dispositivo. Usa `-a` sólo si otros usuarios
  también deben acceder al montaje; FUSE requiere `user_allow_other` en
  `/etc/fuse.conf` para aceptarlo.
- Los nombres `MTR_FILE`, `MIS_FILE`, `CONT`, `TNOC` son los archivos internos
  del FS MTR documentados en `finds.txt`.
