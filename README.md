# Reverse Engineering TASCAM MTR Filesystem (DP-008EX) & FUSE Driver

This repository contains the complete reverse engineering documentation and a Linux FUSE driver for the proprietary/hidden **MTR** filesystem used by TASCAM digital multitrack recorders (such as the DP-008EX, DP-006, and related models).

It allows mounting raw SD card images (or physical block devices) directly under Linux to browse song projects (`SONGxxx`) and extract their individual audio tracks (`track_1.wav` .. `track_8.wav`) as standard PCM WAV files (16-bit, 44.1 kHz, mono) with exact bit-for-bit precision, without requiring manual track export on the device.

---

## 1. Context & SD Card Partition Architecture

An SD card formatted by a TASCAM DP-008EX multitrack recorder features an MBR partition layout consisting of:
1. **Partition 1 (FAT32)**: Occupies the first gigabytes of the card. Used for song backups (`.DAT`) and WAV files exported manually via the recorder menu into the `/WAVE` directory.
2. **MTR Partition (Hidden/Proprietary)**: Starts immediately after the last sector of the FAT32 partition (`(start + sectors) * 512`) and extends to the end of the SD card. It uses TASCAM's proprietary AVFS/TAVFS filesystem designed for real-time 44.1 kHz / 16-bit multitrack stream recording and playback.

### MTR Partition Layout

* **Superblock**: Identified by signature `01 01 00 00 00 00 00 02 00 00 28` near the start of the partition.
* **Song Table**: Located near relative offset `0x228030`. Contains 250 fixed-size 36-byte slots:
  - Song name (8 bytes, e.g., `SONG001 `, `SONG002 `).
  - Allocation state flag at dword offset `+16` (`0` = unused/free, `!= 0` = active song).
* **Per-Song Directory & Metadata Blocks**: Each active song has a dedicated directory and metadata space:
  - `song_base + 0x00000`: Song directory table (32-byte directory entries with standard attributes).
  - `song_base + 0x18000`: `MTR_FILE.bin` (multitrack project metadata).
  - `song_base + 0x30000`: `MIS_FILE.bin` (mixer settings, panning, track levels).
  - `song_base + 0x48000`: `CONT.bin` (master content allocation, event tables, and audio cluster map).
  - `song_base + 0x60000`: `TNOC.bin` (mirror/backup copy of CONT).

### Track-to-Audio Allocation (Cluster Mapping)

1. At `CONT + 0x80`, an array of 8 big-endian dwords indexes the 8 track records:
   $$\text{trk\_rec\_id} = \text{CONT}[0\text{x}80 + (\text{track} - 1) \times 4]$$
2. Record resolution hierarchy:
   $$\text{Track Record (0x80040003)} \to \text{Sub-Record (0x80104900)} \to \text{Event Record (0x90010001)} \to \text{Clip Record (0x80030001)}$$
3. The **Clip Record** defines:
   - Exact length in 16-bit audio samples (`length_in_samples`).
   - Pointer to the assigned **Take Record** (`0x80020007`).
4. The **Take Record** references the block map (`block_map_id`), which points to the block list (`block_list_id`):
   - Audio allocation unit (cluster): Exactly **0x18000 bytes** ($98{,}304$ bytes = $49{,}152$ 16-bit mono samples = $0\text{xc000}$ samples).
   - Block lists support both direct lists (`0x9001`) and indirect lists (`0x9000`) of `[cluster_id, sample_offset]` pairs.
   - Physical partition offset: $\text{offset} = \text{cluster\_id} \times 0\text{x}18000$.
   - Audio is stored as **uncompressed, contiguous 1-channel 16-bit LE PCM** at 44.1 kHz.

For full hexadecimal structures and technical documentation, refer to [`findings.txt`](findings.txt).

---

## 2. FUSE Driver (`mtrfuse`)

`mtrfuse` mounts the MTR partition as a read-only virtual filesystem with the following structure:

```text
mountpoint/
├── info.txt                  # Partition info, base offset, detected songs, and track summary
├── SONG001/
│   ├── tracks/
│   │   ├── track_1.wav       # Track 1 audio (WAV 16-bit 44.1 kHz mono)
│   │   ├── ...
│   │   └── track_8.wav       # Empty tracks return a valid 44-byte WAV header (0 samples)
│   ├── export/               # Mirror of tracks directory for export workflows
│   │   ├── track_1.wav
│   │   └── ...
│   └── metadata/             # Raw binary views of on-disk metadata blocks
│       ├── MTR_FILE.bin
│       ├── MIS_FILE.bin
│       ├── CONT.bin
│       └── TNOC.bin
├── SONG002/
│   └── ...
├── wav/                      # Reserved (empty: no heuristic WAV guessing)
└── raw/                      # Reserved (empty: no heuristic audio guessing)
```

---

## 3. Compilation & Requirements

### Requirements
- Linux kernel with FUSE 3 support.
- Packages: `gcc`, `make`, `libfuse3-dev` (or runtime `libfuse3.so.3` / `fusermount3`).

### Building
```bash
# Build the FUSE driver binary (mtrfuse/mtrfuse)
make -C mtrfuse

# Build the unit test suite (mtrfuse/mtr_selftest)
make -C mtrfuse selftest
```

---

## 4. Usage

### Mounting an SD Card Image
```bash
# Syntax:
./mtrfuse/mtrfuse -i <path_to_image.img> <mountpoint>

# Example:
mkdir -p ./datos
./mtrfuse/mtrfuse -i data.img ./datos
```

The driver automatically detects the start of the MTR partition by reading the partition boundaries in the MBR.

### Command-Line Arguments
- `-i <image>`: Path to SD card image file or raw device node (`/dev/sdX`).
- `-p <offset>`: Manual byte offset for the start of the MTR partition.
- `-s <size>`: Manual byte size limit for the MTR partition.
- `-f`: Foreground mode (do not daemonize).

### Unmounting
```bash
fusermount3 -u ./datos
```

---

## 5. Verification & Unit Tests (`mtr_selftest`)

The `mtr_selftest` utility verifies superblock detection, song table parsing, and bit-for-bit extraction of track audio against known reference files without requiring `/dev/fuse`:

```bash
./mtrfuse/mtr_selftest -i data.img
```

Expected output:
```text
mtrfuse: base=4293596160 size=26974940160 nsongs=3 raw=16
[SELFTEST] superbloque detectado OK (01 01 ...)
[SELFTEST] nsongs=3 (esperado 3: SONG001,SONG002,SONG003)
[SELFTEST] tabla de canciones OK
[SELFTEST] OK: SONG001 track_1 == loop1.wav (BIT-A-BIT EXACTO, 376392 bytes)
[SELFTEST] OK: SONG002 track_3 == loop2.wav (BIT-A-BIT EXACTO, 682840 bytes)
[SELFTEST] OK: SONG003 track_1 == loop4.wav (BIT-A-BIT EXACTO, 198630 bytes)
[SELFTEST] OK: SONG003 track_2 == loop5.wav (BIT-A-BIT EXACTO, 176216 bytes)
[SELFTEST] OK: SONG003 track_7 == loop3.wav (BIT-A-BIT EXACTO, 349050 bytes)
[SELFTEST] OK: pista vacia devuelve cabecera WAV valida de 44 bytes
[SELFTEST] TODOS LOS TESTS PASARON EXITOSAMENTE (100% VERIFICADO)
```

---

## 6. Repository Files

- [`findings.txt`](findings.txt): Comprehensive reverse engineering notes and technical specifications for the MTR format.
- [`mtrfuse/mtr_fuse.c`](mtrfuse/mtr_fuse.c): Main FUSE driver source code with CONT/cluster mapping logic.
- [`mtrfuse/mtr_selftest.c`](mtrfuse/mtr_selftest.c): Test harness entry point.
- [`mtrfuse/Makefile`](mtrfuse/Makefile): Build configuration and compilation targets.
- [`todo.txt`](todo.txt): Sample import and track layout specifications used for verification.
- `loop1.wav` .. `loop5.wav`: Reference audio samples imported into `data.img`.
