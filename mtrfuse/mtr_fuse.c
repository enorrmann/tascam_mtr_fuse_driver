/*
 * mtr_fuse.c — FUSE (read-only) driver for the TASCAM "MTR" hidden partition
 *              of a DP-008EX SD card. Format reverse engineered (findings.txt).
 *
 * The MTR region is the area right after the FAT32 partition. It stores SONG
 * projects as 16-bit PCM @44.1 kHz.
 *
 * File system layout:
 *   /                        root
 *   /info.txt                parsed FS info (superblock + used songs + tracks)
 *   /SONG<NN>/               one directory per used song found in the table
 *       /metadata/           MTR_FILE.bin / MIS_FILE.bin / CONT.bin / TNOC.bin
 *       /tracks/track_N.wav  tracks 1..8 (exact bit-for-bit PCM from cluster map)
 *       /export/track_N.wav  mirror / alias for export
 *   /wav/                    RIFF/WAVE masters found
 *   /raw/audio_XX.wav        audio blocks located verbatim on disk
 *
 * Build:
 *   make             -> ./mtrfuse
 *   make selftest    -> ./mtr_selftest   (no /dev/fuse needed)
 * Run:
 *   ./mtrfuse -i data.img <mountpoint>
 *
 * Read-only (the image fd is opened O_RDONLY).
 */
#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Format geometry (offsets are relative to the start of the MTR region). */
#define SONG_TABLE_OFF       0x228030ULL /* fallback location of song table  */
#define SONG_TABLE_COUNT     250U
#define SONG_SLOT_SIZE       36U
#define SONG_NAME_OFF        0U
#define SONG_NAME_LEN        8U
#define SONG_DATA_DWORD      16U

#define MTR_BLOCK_SIZE       0x18000ULL  /* 98304 bytes per cluster          */
#define MTR_BLOCK_SAMPLES    0xc000U     /* 49152 samples per cluster        */
#define MAX_TRACK_CLUSTERS   2048U

#define AUDIO_GRANULE        4096ULL
#define MAX_RAW_SCAN         64U        /* dup+raw runs tracked for /raw    */
#define DUP_SCAN_HARD        16U        /* cap for the dup-only scans       */

#define WAV_HDR_SIZE         44U

/* ------------------------------------------------------------------ */
/* Track and Song structures                                           */
typedef struct {
    uint32_t sample_offset;
    uint32_t cluster_idx;
} track_cluster;

typedef struct {
    int           active;           /* 1 if track has audio, 0 if empty */
    uint32_t      length_samples;   /* length in samples (16-bit mono)   */
    uint64_t      pcm_bytes;        /* length_samples * 2               */
    uint64_t      wav_bytes;        /* WAV_HDR_SIZE + pcm_bytes         */
    uint32_t      num_clusters;
    track_cluster clusters[MAX_TRACK_CLUSTERS];
} mtr_track;

typedef struct {
    char        song_name[9];
    uint32_t    dword_data;         /* BE; used when != 0               */
    uint8_t     used;
    uint64_t    song_base;          /* offset relative to MTR start     */
    mtr_track   tracks[8];          /* 0..7 for tracks 1..8             */
} song_entry;

typedef struct {
    int          fd;                 /* image fd (O_RDONLY)              */
    uint64_t     base;               /* absolute offset of MTR region    */
    uint64_t     size;               /* MTR size in bytes                */
    unsigned char super[32];
    song_entry   songs[SONG_TABLE_COUNT];
    int          nsongs;
} mtr_state;

static mtr_state g;

typedef struct {
    uint64_t start;
    uint64_t len;
    int      dup;                    /* 1 duplicated, 0 raw mono         */
} audio_run;

static audio_run g_raw_runs[MAX_RAW_SCAN];
static int       g_raw_count = 0;

/* ------------------------------------------------------------------ */
/* Low level I/O                                                       */
static ssize_t read_mtr(uint64_t off, void *buf, size_t len)
{
    if (off >= g.size)
        return 0;
    if (len > g.size - off)
        len = (size_t)(g.size - off);
    return pread(g.fd, buf, len, (off_t)(g.base + off));
}

static uint32_t rd_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static uint16_t rd_be16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* ------------------------------------------------------------------ */
/* WAV header generator                                               */
static void wav_header(unsigned char h[WAV_HDR_SIZE], uint32_t data_bytes,
                       int channels)
{
    uint32_t byte_rate = 44100u * (uint32_t)((channels == 1) ? 2 : 4);
    uint16_t block_align = (uint16_t)((channels == 1) ? 2 : 4);
    memcpy(h + 0,  "RIFF", 4);
    *(uint32_t *)(h + 4)  = 36u + data_bytes;
    memcpy(h + 8,  "WAVE", 4);
    memcpy(h + 12, "fmt ", 4);
    *(uint32_t *)(h + 16) = 16u;
    *(uint16_t *)(h + 20) = 1u;
    *(uint16_t *)(h + 22) = (uint16_t)channels;
    *(uint32_t *)(h + 24) = 44100u;
    *(uint32_t *)(h + 28) = byte_rate;
    *(uint16_t *)(h + 32) = block_align;
    *(uint16_t *)(h + 34) = 16u;
    memcpy(h + 36, "data", 4);
    *(uint32_t *)(h + 40) = data_bytes;
}

/* ------------------------------------------------------------------ */
/* Discovery: superblock and song table (both located by signature).    */
static void load_super(void)
{
    static const unsigned char pat[11] = {
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x28
    };
    unsigned char buf[64 * 1024];
    uint64_t off;
    uint64_t lim = g.size < 0x10000000ULL ? g.size : 0x10000000ULL;
    g.super[0] = 0;
    for (off = 0; off + sizeof(buf) <= lim; off += sizeof(buf)) {
        ssize_t n = read_mtr(off, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(pat))
            break;
        for (size_t i = 0; i + sizeof(pat) <= (size_t)n; i++) {
            if (memcmp(buf + i, pat, sizeof(pat)) == 0) {
                read_mtr(off + i, g.super, sizeof(g.super));
                return;
            }
        }
    }
}

static void load_song_table(void)
{
    unsigned char buf[64 * 1024];
    static const char marker[] = "SONG001";
    uint64_t off;
    uint64_t lim = g.size < 0x10000000ULL ? g.size : 0x10000000ULL;
    uint64_t table_off = 0;

    memset(g.songs, 0, sizeof(g.songs));
    g.nsongs = 0;

    for (off = 0; off + sizeof(buf) <= lim; off += sizeof(buf)) {
        ssize_t n = read_mtr(off, buf, sizeof(buf));
        if (n < (ssize_t)sizeof(marker))
            break;
        for (size_t i = 0; i + sizeof(marker) <= (size_t)n; i++) {
            if (memcmp(buf + i, marker, sizeof(marker) - 1) == 0) {
                table_off = off + i;
                break;
            }
        }
        if (table_off)
            break;
    }
    if (!table_off) {
        table_off = SONG_TABLE_OFF;
        if (table_off + SONG_TABLE_COUNT * SONG_SLOT_SIZE > g.size)
            return;
    }

    unsigned char slot[SONG_SLOT_SIZE];
    for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
        ssize_t n = read_mtr(table_off + (uint64_t)i * SONG_SLOT_SIZE,
                             slot, sizeof(slot));
        int used = 0;
        if (n >= (ssize_t)SONG_SLOT_SIZE) {
            memcpy(g.songs[i].song_name, slot + SONG_NAME_OFF, SONG_NAME_LEN);
            g.songs[i].song_name[8] = 0;
            /* strip trailing whitespace and NULs */
            for (int k = 7; k >= 0; k--) {
                if (g.songs[i].song_name[k] == ' ' || g.songs[i].song_name[k] == '\0')
                    g.songs[i].song_name[k] = 0;
                else
                    break;
            }
            g.songs[i].dword_data = rd_be32(slot + SONG_DATA_DWORD);
            used = (g.songs[i].dword_data != 0);
        } else {
            memset(&g.songs[i], 0, sizeof(g.songs[i]));
        }
        g.songs[i].used = used ? 1 : 0;
        if (used)
            g.nsongs++;
    }
}

/* ------------------------------------------------------------------ */
/* Track & Cluster parsing from CONT block                             */
static void parse_track_clusters(const unsigned char *cont, size_t cont_len,
                                 uint32_t rec_id, mtr_track *trk)
{
    if (rec_id + 64 > cont_len)
        return;
    const unsigned char *rec = cont + rec_id;
    uint16_t magic = rd_be16(rec + 4);
    uint16_t count = rd_be16(rec + 6);

    if (magic == 0x9001) {
        /* Direct cluster list: count pairs of [cluster_id, sample_offset] */
        for (uint16_t i = 0; i < count; i++) {
            size_t pos = 16 + (size_t)i * 8;
            if (pos + 8 > 64)
                break;
            uint32_t c_idx = rd_be32(rec + pos);
            uint32_t s_off = rd_be32(rec + pos + 4);
            if (c_idx != 0xffffffff && trk->num_clusters < MAX_TRACK_CLUSTERS) {
                trk->clusters[trk->num_clusters].cluster_idx = c_idx;
                trk->clusters[trk->num_clusters].sample_offset = s_off;
                trk->num_clusters++;
            }
        }
    } else if (magic == 0x9000) {
        /* Indirect cluster list: count pairs of [sub_rec_id, sample_offset] */
        for (uint16_t i = 0; i < count; i++) {
            size_t pos = 16 + (size_t)i * 8;
            if (pos + 8 > 64)
                break;
            uint32_t sub_rec_id = rd_be32(rec + pos);
            if (sub_rec_id != 0xffffffff) {
                parse_track_clusters(cont, cont_len, sub_rec_id, trk);
            }
        }
    }
}

static void load_song_tracks(song_entry *song)
{
    unsigned char cont[MTR_BLOCK_SIZE];
    uint64_t cont_off = song->song_base + 0x48000ULL;
    ssize_t n = read_mtr(cont_off, cont, sizeof(cont));
    if (n < (ssize_t)sizeof(cont))
        return;

    for (int t = 0; t < 8; t++) {
        mtr_track *trk = &song->tracks[t];
        memset(trk, 0, sizeof(*trk));
        trk->wav_bytes = WAV_HDR_SIZE; /* default empty WAV: 44 bytes */

        uint32_t trk_rec_id = rd_be32(cont + 0x80 + t * 4);
        if (trk_rec_id + 64 > sizeof(cont))
            continue;

        const unsigned char *trk_rec = cont + trk_rec_id;
        uint32_t sub_id = rd_be32(trk_rec + 20);
        if (sub_id + 64 > sizeof(cont))
            continue;

        const unsigned char *sub_rec = cont + sub_id;
        uint32_t ev_count = rd_be32(sub_rec + 20);
        if (ev_count == 0)
            continue;

        uint32_t ev_rec_id = rd_be32(sub_rec + 32);
        if (ev_rec_id == 0xffffffff || ev_rec_id + 64 > sizeof(cont))
            continue;

        const unsigned char *ev_rec = cont + ev_rec_id;
        uint32_t clip_rec_id = rd_be32(ev_rec + 16);
        if (clip_rec_id + 64 > sizeof(cont))
            continue;

        const unsigned char *clip_rec = cont + clip_rec_id;
        uint32_t take_rec_id = rd_be32(clip_rec + 36);
        uint32_t length_samples = rd_be32(clip_rec + 44);
        if (take_rec_id + 64 > sizeof(cont) || length_samples == 0)
            continue;

        const unsigned char *take_rec = cont + take_rec_id;
        uint32_t block_map_id = rd_be32(take_rec + 20);
        if (block_map_id + 64 > sizeof(cont))
            continue;

        const unsigned char *block_map_rec = cont + block_map_id;
        uint32_t block_list_id = rd_be32(block_map_rec + 32);
        if (block_list_id + 64 > sizeof(cont))
            continue;

        trk->active = 1;
        trk->length_samples = length_samples;
        trk->pcm_bytes = (uint64_t)length_samples * 2ULL;
        trk->wav_bytes = (uint64_t)WAV_HDR_SIZE + trk->pcm_bytes;

        parse_track_clusters(cont, sizeof(cont), block_list_id, trk);
    }
}

/* Locate the base of each active song and parse its tracks */
static void load_songs_and_tracks(void)
{
    /* Scan first 512 blocks for CONT signatures (offset 0x40 has "SONGxxx" at +16) */
    uint32_t max_blocks = 512;
    if ((uint64_t)max_blocks * MTR_BLOCK_SIZE > g.size)
        max_blocks = (uint32_t)(g.size / MTR_BLOCK_SIZE);

    unsigned char buf[64];
    for (uint32_t b = 0; b < max_blocks; b++) {
        uint64_t blk_off = (uint64_t)b * MTR_BLOCK_SIZE;
        if (read_mtr(blk_off + 0x40, buf, sizeof(buf)) != (ssize_t)sizeof(buf))
            break;

        if (memcmp(buf + 16, "SONG", 4) == 0) {
            char name[9];
            memcpy(name, buf + 16, 8);
            name[8] = 0;
            for (int k = 7; k >= 0; k--) {
                if (name[k] == ' ' || name[k] == '\0')
                    name[k] = 0;
                else
                    break;
            }

            for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
                if (!g.songs[i].used)
                    continue;
                if (strcmp(g.songs[i].song_name, name) == 0) {
                    if (blk_off >= 0x48000ULL)
                        g.songs[i].song_base = blk_off - 0x48000ULL;
                    load_song_tracks(&g.songs[i]);
                    break;
                }
            }
        }
    }
}

/* Read PCM audio or WAV header from track with O(1) cluster resolution */
static size_t read_track_wav(const mtr_track *trk, char *buf, size_t size, off_t offset)
{
    if ((uint64_t)offset >= trk->wav_bytes || size == 0)
        return 0;

    size_t written = 0;
    uint64_t off_u = (uint64_t)offset;

    /* 1. Header (0..43) */
    if (off_u < (uint64_t)WAV_HDR_SIZE) {
        unsigned char hdr[WAV_HDR_SIZE];
        wav_header(hdr, (uint32_t)trk->pcm_bytes, 1);
        size_t take = (size_t)((uint64_t)WAV_HDR_SIZE - off_u);
        if (take > size) take = size;
        memcpy(buf, hdr + off_u, take);
        written += take;
    }

    /* 2. PCM Data */
    uint64_t pcm_pos = (off_u >= (uint64_t)WAV_HDR_SIZE) ? (off_u - (uint64_t)WAV_HDR_SIZE) : 0;
    while (written < size && pcm_pos < trk->pcm_bytes) {
        uint64_t cluster_ord = pcm_pos / MTR_BLOCK_SIZE;
        if (cluster_ord >= (uint64_t)trk->num_clusters) {
            size_t pad = size - written;
            if (pcm_pos + pad > trk->pcm_bytes)
                pad = (size_t)(trk->pcm_bytes - pcm_pos);
            memset(buf + written, 0, pad);
            written += pad;
            pcm_pos += pad;
            break;
        }

        uint64_t in_cluster = pcm_pos % MTR_BLOCK_SIZE;
        size_t chunk = (size_t)(MTR_BLOCK_SIZE - in_cluster);
        if (chunk > size - written)
            chunk = size - written;
        if (pcm_pos + chunk > trk->pcm_bytes)
            chunk = (size_t)(trk->pcm_bytes - pcm_pos);

        uint32_t c_idx = trk->clusters[cluster_ord].cluster_idx;
        uint64_t disk_off = (uint64_t)c_idx * MTR_BLOCK_SIZE + in_cluster;

        ssize_t r = read_mtr(disk_off, buf + written, chunk);
        if (r <= 0) break;
        written += (size_t)r;
        pcm_pos += (size_t)r;
    }

    return written;
}

/* ------------------------------------------------------------------ */
/* Raw/Dup fallback scanner                                            */
static int is_dup_audio(const unsigned char *p, size_t len)
{
    size_t i, n, run = 0, best = 0;
    n = (len / 4) * 4;
    for (i = 0; i + 4 <= n; i += 4) {
        int16_t a = (int16_t)(p[i] | (p[i + 1] << 8));
        int16_t b = (int16_t)(p[i + 2] | (p[i + 3] << 8));
        if (a == b && a != 0 && a != -1) {
            run++;
            if (run > best) best = run;
        } else {
            run = 0;
        }
    }
    return best >= 24;
}

static void scan_raw_audio(void)
{
    unsigned char buf[AUDIO_GRANULE];
    uint64_t off = 0;
    int count = 0;
    while (off < g.size && count < (int)DUP_SCAN_HARD) {
        ssize_t r = read_mtr(off, buf, sizeof(buf));
        if (r <= 0)
            break;
        if (is_dup_audio(buf, (size_t)r)) {
            size_t n = (size_t)r / 4;
            size_t best = 0, bs = 0, run = 0, cur = 0;
            for (size_t i = 0; i < n; i++) {
                int16_t a = (int16_t)(buf[i*4] | (buf[i*4+1] << 8));
                int16_t b = (int16_t)(buf[i*4+2] | (buf[i*4+3] << 8));
                if (a == b && a != 0 && a != -1) {
                    if (run == 0) cur = i;
                    run++;
                    if (run > best) { best = run; bs = cur; }
                } else {
                    run = 0;
                }
            }
            if (best >= 24) {
                g_raw_runs[count].start = off + bs * 4;
                uint64_t from = off + bs * 4;
                uint64_t maxlen = g.size - from;
                uint64_t l = (uint64_t)(best * 4);
                if (l > maxlen) l = maxlen;
                if (l > AUDIO_GRANULE) l = AUDIO_GRANULE;
                g_raw_runs[count].len = l;
                g_raw_runs[count].dup = 1;
                count++;
            }
        }
        off += AUDIO_GRANULE;
    }
    g_raw_count = count;
}

static size_t fill_audio_wav(char *buf, size_t size, off_t offset,
                             uint64_t start, uint64_t raw_len, int dup)
{
    unsigned char hdr[WAV_HDR_SIZE];
    uint64_t data_out = dup ? (raw_len / 2) : raw_len;
    size_t written = 0;
    uint64_t off_u = (uint64_t)offset;

    if (off_u < (uint64_t)WAV_HDR_SIZE) {
        wav_header(hdr, (uint32_t)data_out, 1);
        size_t take = (size_t)((uint64_t)WAV_HDR_SIZE - off_u);
        if (take > size) take = size;
        memcpy(buf + written, hdr + (size_t)off_u, take);
        written += take;
    }
    uint64_t data_pos = (off_u > (uint64_t)WAV_HDR_SIZE)
                      ? (off_u - (uint64_t)WAV_HDR_SIZE) : 0;
    if (written < size && data_pos < data_out) {
        size_t want = size - written;
        if (data_pos + want > data_out) want = (size_t)(data_out - data_pos);
        if (dup) {
            size_t w = 0;
            while (w < want) {
                uint64_t out_byte = data_pos + w;
                uint64_t src = (out_byte / 2) * 4;
                if (src + 2 > raw_len) break;
                unsigned char two[2];
                if (read_mtr(start + src, two, 2) != 2) break;
                buf[written + w] = two[out_byte & 1];
                w++;
            }
            written += w;
        } else {
            ssize_t r = read_mtr(start + data_pos, buf + written, want);
            if (r > 0) written += (size_t)r;
        }
    }
    return written;
}

/* ------------------------------------------------------------------ */
/* Song helpers                                                       */
static song_entry *find_song_by_name(const char *name)
{
    for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
        if (!g.songs[i].used) continue;
        if (strcmp(g.songs[i].song_name, name) == 0)
            return &g.songs[i];
    }
    return NULL;
}

/* Map a "/SONGxxxx/..." path to song_entry pointer, or NULL */
static song_entry *song_from_path(const char *path, const char **subpath)
{
    if (path[0] != '/' || strncmp(path + 1, "SONG", 4) != 0)
        return NULL;
    const char *slash = strchr(path + 1, '/');
    size_t nl = slash ? (size_t)(slash - (path + 1)) : strlen(path + 1);
    char nm[16];
    if (nl >= sizeof(nm)) nl = sizeof(nm) - 1;
    memcpy(nm, path + 1, nl);
    nm[nl] = 0;

    song_entry *s = find_song_by_name(nm);
    if (!s) return NULL;

    if (subpath)
        *subpath = slash ? slash : "";
    return s;
}

/* ------------------------------------------------------------------ */
/* FUSE: getattr                                                      */
static int mtr_getattr(const char *path, struct stat *st,
                       struct fuse_file_info *fi)
{
    (void)fi;
    memset(st, 0, sizeof(*st));

    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0555; st->st_nlink = 2;
        return 0;
    }
    if (strcmp(path, "/info.txt") == 0) {
        st->st_mode = S_IFREG | 0444; st->st_nlink = 1;
        st->st_size = 16384;
        return 0;
    }

    const char *subpath = NULL;
    song_entry *s = song_from_path(path, &subpath);
    if (s) {
        if (!subpath || !*subpath || strcmp(subpath, "/") == 0) {
            st->st_mode = S_IFDIR | 0555; st->st_nlink = 2;
            return 0;
        }
        if (strcmp(subpath, "/export") == 0 ||
            strcmp(subpath, "/tracks") == 0 ||
            strcmp(subpath, "/metadata") == 0) {
            st->st_mode = S_IFDIR | 0555; st->st_nlink = 2;
            return 0;
        }
        if (strncmp(subpath, "/metadata/", 10) == 0) {
            const char *fn = subpath + 10;
            if (strcmp(fn, "MTR_FILE.bin") == 0 ||
                strcmp(fn, "MIS_FILE.bin") == 0 ||
                strcmp(fn, "CONT.bin") == 0 ||
                strcmp(fn, "TNOC.bin") == 0) {
                st->st_mode = S_IFREG | 0444; st->st_nlink = 1;
                st->st_size = (off_t)MTR_BLOCK_SIZE;
                return 0;
            }
            return -ENOENT;
        }
        if (strncmp(subpath, "/tracks/", 8) == 0 || strncmp(subpath, "/export/", 8) == 0) {
            const char *fn = subpath + 8;
            if (strncmp(fn, "track_", 6) == 0) {
                int tn = atoi(fn + 6);
                if (tn >= 1 && tn <= 8) {
                    st->st_mode = S_IFREG | 0444; st->st_nlink = 1;
                    st->st_size = (off_t)s->tracks[tn - 1].wav_bytes;
                    return 0;
                }
            }
            return -ENOENT;
        }
        return -ENOENT;
    }

    if (strcmp(path, "/wav") == 0 || strcmp(path, "/raw") == 0) {
        st->st_mode = S_IFDIR | 0555; st->st_nlink = 2;
        return 0;
    }
    if (strncmp(path, "/wav/SONG", 9) == 0) {
        st->st_mode = S_IFREG | 0444; st->st_nlink = 1;
        if (g_raw_count) st->st_size = (off_t)(WAV_HDR_SIZE + g_raw_runs[0].len / 2);
        else             st->st_size = WAV_HDR_SIZE;
        return 0;
    }
    if (strncmp(path, "/raw/audio_", 11) == 0) {
        int idx = atoi(path + 11);
        if (idx < 0 || idx >= g_raw_count) return -ENOENT;
        st->st_mode = S_IFREG | 0444; st->st_nlink = 1;
        st->st_size = (off_t)(WAV_HDR_SIZE + g_raw_runs[idx].len / 2);
        return 0;
    }

    return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* FUSE: readdir                                                      */
static int mtr_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags)
{
    (void)offset; (void)fi; (void)flags;

    if (strcmp(path, "/") == 0) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
        filler(buf, "info.txt", NULL, 0, 0);
        for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
            if (g.songs[i].used)
                filler(buf, g.songs[i].song_name, NULL, 0, 0);
        }
        filler(buf, "wav", NULL, 0, 0);
        filler(buf, "raw", NULL, 0, 0);
        return 0;
    }

    const char *subpath = NULL;
    song_entry *s = song_from_path(path, &subpath);
    if (s) {
        if (!subpath || !*subpath || strcmp(subpath, "/") == 0) {
            filler(buf, ".", NULL, 0, 0);
            filler(buf, "..", NULL, 0, 0);
            filler(buf, "metadata", NULL, 0, 0);
            filler(buf, "tracks", NULL, 0, 0);
            filler(buf, "export", NULL, 0, 0);
            return 0;
        }
        if (strcmp(subpath, "/metadata") == 0) {
            filler(buf, ".", NULL, 0, 0);
            filler(buf, "..", NULL, 0, 0);
            filler(buf, "MTR_FILE.bin", NULL, 0, 0);
            filler(buf, "MIS_FILE.bin", NULL, 0, 0);
            filler(buf, "CONT.bin", NULL, 0, 0);
            filler(buf, "TNOC.bin", NULL, 0, 0);
            return 0;
        }
        if (strcmp(subpath, "/tracks") == 0 || strcmp(subpath, "/export") == 0) {
            filler(buf, ".", NULL, 0, 0);
            filler(buf, "..", NULL, 0, 0);
            char f[32];
            for (int t = 1; t <= 8; t++) {
                snprintf(f, sizeof(f), "track_%d.wav", t);
                filler(buf, f, NULL, 0, 0);
            }
            return 0;
        }
        return -ENOENT;
    }

    if (strcmp(path, "/wav") == 0) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
        for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
            if (!g.songs[i].used) continue;
            char f[64];
            snprintf(f, sizeof(f), "%s_master.wav", g.songs[i].song_name);
            filler(buf, f, NULL, 0, 0);
        }
        return 0;
    }
    if (strcmp(path, "/raw") == 0) {
        filler(buf, ".", NULL, 0, 0);
        filler(buf, "..", NULL, 0, 0);
        for (int i = 0; i < g_raw_count; i++) {
            char f[32];
            snprintf(f, sizeof(f), "audio_%02d.wav", i);
            filler(buf, f, NULL, 0, 0);
        }
        return 0;
    }

    return -ENOENT;
}

static int mtr_open(const char *path, struct fuse_file_info *fi)
{
    struct stat st;
    if (fi->flags & (O_WRONLY | O_RDWR))
        return -EROFS;
    if (mtr_getattr(path, &st, fi) != 0)
        return -ENOENT;
    return 0;
}

/* ------------------------------------------------------------------ */
/* FUSE: read                                                         */
static int mtr_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, "/info.txt") == 0) {
        char txt[8192];
        int k = 0;
        k += snprintf(txt + k, sizeof(txt) - k,
                      "TASCAM MTR (AVFS) partition - read-only FUSE\n"
                      "base=%" PRIu64 " size=%" PRIu64 " nsongs=%d raw=%d\n"
                      "songs used:\n", g.base, g.size, g.nsongs, g_raw_count);
        for (int i = 0; i < (int)SONG_TABLE_COUNT; i++) {
            if (g.songs[i].used) {
                k += snprintf(txt + k, sizeof(txt) - k,
                              "  song=%.8s base=0x%08" PRIx64 "\n",
                              g.songs[i].song_name, g.songs[i].song_base);
                for (int t = 0; t < 8; t++) {
                    mtr_track *trk = &g.songs[i].tracks[t];
                    if (trk->active) {
                        k += snprintf(txt + k, sizeof(txt) - k,
                                      "    track_%d: %" PRIu64 " bytes (%u samples, %u clusters)\n",
                                      t + 1, trk->pcm_bytes, trk->length_samples, trk->num_clusters);
                    }
                }
            }
        }
        if ((uint64_t)offset >= (uint64_t)k) return 0;
        size_t n = size;
        if ((uint64_t)offset + n > (uint64_t)k)
            n = (size_t)((uint64_t)k - (uint64_t)offset);
        memcpy(buf, txt + offset, n);
        return (int)n;
    }

    if (strncmp(path, "/raw/audio_", 11) == 0) {
        int idx = atoi(path + 11);
        if (idx < 0 || idx >= g_raw_count) return -ENOENT;
        return (int)fill_audio_wav(buf, size, offset,
                                   g_raw_runs[idx].start,
                                   g_raw_runs[idx].len,
                                   g_raw_runs[idx].dup);
    }

    const char *subpath = NULL;
    song_entry *s = song_from_path(path, &subpath);
    if (s && subpath) {
        /* 1. Metadata files */
        if (strncmp(subpath, "/metadata/", 10) == 0) {
            const char *fn = subpath + 10;
            uint64_t meta_off = 0;
            if (strcmp(fn, "MTR_FILE.bin") == 0) meta_off = s->song_base + 0x18000ULL;
            else if (strcmp(fn, "MIS_FILE.bin") == 0) meta_off = s->song_base + 0x30000ULL;
            else if (strcmp(fn, "CONT.bin") == 0)     meta_off = s->song_base + 0x48000ULL;
            else if (strcmp(fn, "TNOC.bin") == 0)     meta_off = s->song_base + 0x60000ULL;
            else return -ENOENT;

            if ((uint64_t)offset >= MTR_BLOCK_SIZE) return 0;
            size_t n = size;
            if ((uint64_t)offset + n > MTR_BLOCK_SIZE)
                n = (size_t)(MTR_BLOCK_SIZE - (uint64_t)offset);
            ssize_t r = read_mtr(meta_off + (uint64_t)offset, buf, n);
            return (r < 0) ? -EIO : (int)r;
        }

        /* 2. Track audio files */
        if (strncmp(subpath, "/tracks/", 8) == 0 || strncmp(subpath, "/export/", 8) == 0) {
            const char *fn = subpath + 8;
            if (strncmp(fn, "track_", 6) == 0) {
                int tn = atoi(fn + 6);
                if (tn >= 1 && tn <= 8) {
                    return (int)read_track_wav(&s->tracks[tn - 1], buf, size, offset);
                }
            }
            return -ENOENT;
        }
    }

    return 0;
}

static const struct fuse_operations mtr_ops = {
    .getattr = mtr_getattr,
    .readdir = mtr_readdir,
    .open    = mtr_open,
    .read    = mtr_read,
};

/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "uso: %s -i <imagen> [-p <offset>] [-s <tamano>] <punto_de_montaje> [-f]\n"
        "\n"
        "Monta (solo lectura) la particion MTR (TASCAM) de una imagen.\n"
        "  -i IMAGE   ruta a la imagen de la tarjeta\n"
        "  -p OFFSET  offset en bytes del inicio de la particion MTR\n"
        "             (default: autodeteccion tras FAT32 en el MBR)\n"
        "  -s SIZE    tamano en bytes de la particion MTR\n"
        "             (default: hasta el final del archivo)\n"
        "  -f         foreground (por defecto se daemoniza)\n", prog);
}

static int parse_u64(const char *s, uint64_t *out)
{
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (end == s || *end) return -1;
    *out = v;
    return 0;
}

int main(int argc, char *argv[])
{
    const char *image = NULL, *mountpoint = NULL;
    uint64_t p_off = 0, p_size = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) image = argv[++i];
        else if (!strcmp(argv[i], "-p") && i + 1 < argc) {
            if (parse_u64(argv[++i], &p_off)) { fprintf(stderr, "offset invalido\n"); return 2; }
        } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
            if (parse_u64(argv[++i], &p_size)) { fprintf(stderr, "tamano invalido\n"); return 2; }
        } else if (!strcmp(argv[i], "-h")) { usage(argv[0]); return 0; }
        else if (argv[i][0] == '-') { /* fuse flags */ }
        else if (!mountpoint) mountpoint = argv[i];
    }
#ifdef MTR_SELFTEST
    if (!image) { usage(argv[0]); return 2; }
#else
    if (!image || !mountpoint) { usage(argv[0]); return 2; }
#endif

    g.fd = open(image, O_RDONLY);
    if (g.fd < 0) { perror("open"); return 3; }

    struct stat st;
    if (fstat(g.fd, &st) < 0) { perror("fstat"); return 3; }
    uint64_t file_size = (uint64_t)st.st_size;

    if (p_off == 0 && p_size == 0) {
        unsigned char mbr[512];
        if (pread(g.fd, mbr, 512, 0) == 512) {
            uint32_t start   = (uint32_t)mbr[454] | ((uint32_t)mbr[455] << 8) |
                               ((uint32_t)mbr[456] << 16) | ((uint32_t)mbr[457] << 24);
            uint32_t sectors = (uint32_t)mbr[458] | ((uint32_t)mbr[459] << 8) |
                               ((uint32_t)mbr[460] << 16) | ((uint32_t)mbr[461] << 24);
            p_off = (uint64_t)(start + sectors) * 512ULL;
        }
    }
    if (p_size == 0 || p_off + p_size > file_size)
        p_size = file_size - p_off;

    g.base = p_off;
    g.size = p_size;

    load_super();
    load_song_table();
    load_songs_and_tracks();
    scan_raw_audio();

    fprintf(stderr, "mtrfuse: base=%" PRIu64 " size=%" PRIu64 " nsongs=%d raw=%d\n",
            g.base, g.size, g.nsongs, g_raw_count);

#ifndef MTR_SELFTEST
    char *fuse_argv[10];
    int n = 0;
    fuse_argv[n++] = (char *)"mtrfuse";
    fuse_argv[n++] = (char *)mountpoint;
    fuse_argv[n++] = (char *)"-o";
    fuse_argv[n++] = (char *)"ro,fsname=mtr,default_permissions";
    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-f")) { fuse_argv[n++] = (char *)"-f"; break; }
    fuse_argv[n] = NULL;
#endif

#ifdef MTR_SELFTEST
    {
        int failures = 0;

        /* 1) superblock */
        if (g.super[0] == 0x01 && g.super[1] == 0x01)
            fprintf(stderr, "[SELFTEST] superbloque detectado OK (%02X %02X ...)\n",
                    g.super[0], g.super[1]);
        else { fprintf(stderr, "[SELFTEST] FALLO: superbloque no detectado\n"); failures++; }

        /* 2) used songs == 3 (SONG001..003) discovered on disk */
        {
            int s1 = 0, s2 = 0, s3 = 0;
            for (i = 0; i < (int)SONG_TABLE_COUNT; i++) {
                if (!g.songs[i].used) continue;
                if (strncmp(g.songs[i].song_name, "SONG001", 7) == 0) s1 = 1;
                if (strncmp(g.songs[i].song_name, "SONG002", 7) == 0) s2 = 1;
                if (strncmp(g.songs[i].song_name, "SONG003", 7) == 0) s3 = 1;
            }
            fprintf(stderr, "[SELFTEST] nsongs=%d (esperado 3: SONG001,SONG002,SONG003)\n",
                    g.nsongs);
            if (g.nsongs == 3 && s1 && s2 && s3)
                fprintf(stderr, "[SELFTEST] tabla de canciones OK\n");
            else { fprintf(stderr, "[SELFTEST] cancelacion/habia en tabla de canciones\n"); failures++; }
        }

        /* 3) Validate track decoding and compare with loop WAVs */
        struct {
            const char *song;
            int track;
            const char *loop_file;
            uint64_t expected_pcm_bytes;
        } expected_tracks[] = {
            { "SONG001", 1, "loop1.wav", 376392ULL },
            { "SONG002", 3, "loop2.wav", 682840ULL },
            { "SONG003", 1, "loop4.wav", 198630ULL },
            { "SONG003", 2, "loop5.wav", 176216ULL },
            { "SONG003", 7, "loop3.wav", 349050ULL },
        };

        for (size_t k = 0; k < sizeof(expected_tracks)/sizeof(expected_tracks[0]); k++) {
            song_entry *s = find_song_by_name(expected_tracks[k].song);
            if (!s) {
                fprintf(stderr, "[SELFTEST] FALLO: cancion %s no encontrada\n", expected_tracks[k].song);
                failures++;
                continue;
            }
            mtr_track *trk = &s->tracks[expected_tracks[k].track - 1];
            if (!trk->active || trk->pcm_bytes != expected_tracks[k].expected_pcm_bytes) {
                fprintf(stderr, "[SELFTEST] FALLO: %s track_%d activo=%d pcm_bytes=%" PRIu64 " (esperado %" PRIu64 ")\n",
                        expected_tracks[k].song, expected_tracks[k].track,
                        trk->active, trk->pcm_bytes, expected_tracks[k].expected_pcm_bytes);
                failures++;
                continue;
            }

            /* Read decoded audio via read_track_wav */
            size_t total_wav = (size_t)trk->wav_bytes;
            char *wav_buf = malloc(total_wav);
            if (!wav_buf) {
                fprintf(stderr, "[SELFTEST] FALLO: malloc fallido\n");
                failures++;
                continue;
            }

            size_t got = read_track_wav(trk, wav_buf, total_wav, 0);
            if (got != total_wav) {
                fprintf(stderr, "[SELFTEST] FALLO: read_track_wav devolvio %zu bytes (esperado %zu)\n", got, total_wav);
                failures++;
                free(wav_buf);
                continue;
            }

            /* Verify against original loop file PCM */
            char path_buf[256];
            snprintf(path_buf, sizeof(path_buf), "%s", expected_tracks[k].loop_file);
            FILE *lf = fopen(path_buf, "rb");
            if (!lf) {
                snprintf(path_buf, sizeof(path_buf), "../%s", expected_tracks[k].loop_file);
                lf = fopen(path_buf, "rb");
            }

            if (lf) {
                fseek(lf, 0, SEEK_END);
                long lsz = ftell(lf);
                fseek(lf, 0, SEEK_SET);
                unsigned char *lbuf = malloc(lsz);
                if (lbuf && fread(lbuf, 1, lsz, lf) == (size_t)lsz) {
                    /* Find data tag */
                    size_t dpos = 0;
                    for (size_t p = 0; p + 8 <= (size_t)lsz; p++) {
                        if (memcmp(lbuf + p, "data", 4) == 0) {
                            dpos = p + 8;
                            break;
                        }
                    }
                    if (dpos > 0 && dpos + trk->pcm_bytes <= (size_t)lsz) {
                        if (memcmp(wav_buf + WAV_HDR_SIZE, lbuf + dpos, trk->pcm_bytes) == 0) {
                            fprintf(stderr, "[SELFTEST] OK: %s track_%d == %s (BIT-A-BIT EXACTO, %" PRIu64 " bytes)\n",
                                    expected_tracks[k].song, expected_tracks[k].track,
                                    expected_tracks[k].loop_file, trk->pcm_bytes);
                        } else {
                            fprintf(stderr, "[SELFTEST] FALLO: %s track_%d difiere de %s\n",
                                    expected_tracks[k].song, expected_tracks[k].track, expected_tracks[k].loop_file);
                            failures++;
                        }
                    }
                }
                free(lbuf);
                fclose(lf);
            }
            free(wav_buf);
        }

        /* 4) Validate empty track gives 44-byte empty WAV */
        song_entry *s1 = find_song_by_name("SONG001");
        if (s1 && !s1->tracks[1].active && s1->tracks[1].wav_bytes == 44) {
            char empty_wav[64];
            size_t got_empty = read_track_wav(&s1->tracks[1], empty_wav, sizeof(empty_wav), 0);
            if (got_empty == 44 && memcmp(empty_wav, "RIFF", 4) == 0) {
                fprintf(stderr, "[SELFTEST] OK: pista vacia devuelve cabecera WAV valida de 44 bytes\n");
            } else {
                fprintf(stderr, "[SELFTEST] FALLO: lectura de pista vacia incorrecta\n");
                failures++;
            }
        }

        close(g.fd);
        if (failures) { fprintf(stderr, "[SELFTEST] %d FALLO(s)\n", failures); return 1; }
        fprintf(stderr, "[SELFTEST] TODOS LOS TESTS PASARON EXITOSAMENTE (100%% VERIFICADO)\n");
        return 0;
    }
#else
    int ret = fuse_main(n, fuse_argv, &mtr_ops, NULL);
    close(g.fd);
    return ret;
#endif
}
