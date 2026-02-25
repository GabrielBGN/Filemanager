// fs.c - CSE 3320 Spring 2026 - Programming Assignment 2 - File System Internals
// Portable mini filesystem in a disk-image file using 256-byte blocks.
//
// Build (MinGW gcc / gcc):
//   gcc -O2 -Wall -Wextra -std=c11 fs.c -o FS
//
// Run:
//   ./FS   (interactive shell)
//
// Commands implemented:
//   Createfs, Openfs, Savefs, Formatfs, User, List, Put, Get, Rename, Remove, Link, Unlink, Quit
//
// Notes:
// - Flat directory via File Name Table (FNT)
// - DABPT provides metadata + pointer to Block Pointer Table (BPT) head
// - BPT entries contain 8x 32-bit pointers; ptr[0..6] data blocks, ptr[7] chains to another BPT entry index
// - Free space tracked by bitmap over disk blocks
//
// Limits: filenames max 56, usernames max 40.

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_SIZE 256u
#define MAGIC "FS01"
#define NILPTR 0xFFFFFFFFu

#define MAX_TOKENS 8
#define MAX_LINE 1024

// ---------- Packing (MinGW/GCC safe) ----------
#pragma pack(push, 1)
#define PACKED

// Superblock must be exactly 256 bytes (one block).
// magic[4] + 13*uint32_t = 4 + 52 = 56 bytes header => 200 bytes padding.
typedef struct PACKED {
    char     magic[4];          // "FS01"
    uint32_t totalBlocks;

    uint32_t fntEntries;        // number of FNT entries
    uint32_t dabptEntries;      // number of DABPT entries

    uint32_t bitmapStart;       // block index
    uint32_t bitmapBlocks;      // number of blocks

    uint32_t fntStart;          // block index
    uint32_t fntBlocks;

    uint32_t dabptStart;        // block index
    uint32_t dabptBlocks;

    uint32_t bptStart;          // block index
    uint32_t bptBlocks;         // number of blocks used for BPT region
    uint32_t bptEntries;        // total BPT entries available in region

    uint32_t dataStart;         // first data block index

    uint8_t  reserved[BLOCK_SIZE - (4 + 13 * 4)];
} Superblock;

typedef struct PACKED {
    char     name[56];
    uint32_t dabptIndex;  // inode pointer (index into DABPT)
    uint8_t  inUse;
    uint8_t  pad[3];      // make 64 bytes
} FNTEntry;               // 64 bytes -> 4 per block

typedef struct PACKED {
    uint32_t fileSize;
    uint64_t mtime;       // seconds since epoch
    uint32_t bptHead;     // BPT entry index (not block)
    char     user[40];
    uint16_t linkCount;
    uint8_t  inUse;
    uint8_t  pad[5];      // make 64 bytes
} DABPTEntry;             // 64 bytes -> 4 per block

typedef struct PACKED {
    uint32_t ptr[8];      // ptr[0..6] data blocks; ptr[7] = next BPT entry index or NILPTR
} BPTEntry;               // 32 bytes -> 8 per block

#pragma pack(pop)

// Compile-time size checks
_Static_assert(sizeof(Superblock) == BLOCK_SIZE, "Superblock must be 256 bytes");
_Static_assert(sizeof(FNTEntry) == 64, "FNTEntry must be 64 bytes");
_Static_assert(sizeof(DABPTEntry) == 64, "DABPTEntry must be 64 bytes");
_Static_assert(sizeof(BPTEntry) == 32, "BPTEntry must be 32 bytes");

// ---------- Globals ----------
static FILE *gDisk = NULL;
static char  gDiskPath[512] = {0};
static Superblock gSB;
static int gFormatted = 0;
static char gUser[41] = "default"; // active user

// ---------- Utilities ----------
static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = 0;
}

static int tokenize(char *line, char *tok[], int maxTok) {
    int n = 0;
    char *p = line;
    while (*p && n < maxTok) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        tok[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = 0;
    }
    return n;
}

static uint32_t blocks_for_bytes(uint32_t bytes) {
    return (bytes + BLOCK_SIZE - 1) / BLOCK_SIZE;
}

static uint32_t fnt_blocks(uint32_t entries) {
    return (entries + 3) / 4; // 4 entries per block
}

static uint32_t dabpt_blocks(uint32_t entries) {
    return (entries + 3) / 4; // 4 entries per block
}

static uint32_t bpt_entries_per_block(void) {
    return BLOCK_SIZE / (uint32_t)sizeof(BPTEntry); // 8
}

static uint32_t bitmap_blocks(uint32_t totalBlocks) {
    uint32_t bytes = (totalBlocks + 7) / 8;
    return blocks_for_bytes(bytes);
}

static const char* base_name(const char *path) {
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    const char *s = s1 > s2 ? s1 : s2;
    return s ? s + 1 : path;
}

// ---------- Block I/O ----------
static int read_block(uint32_t block, uint8_t out[BLOCK_SIZE]) {
    if (!gDisk) return -1;
    if (fseek(gDisk, (long)block * (long)BLOCK_SIZE, SEEK_SET) != 0) return -1;
    size_t r = fread(out, 1, BLOCK_SIZE, gDisk);
    return (r == BLOCK_SIZE) ? 0 : -1;
}

static int write_block(uint32_t block, const uint8_t in[BLOCK_SIZE]) {
    if (!gDisk) return -1;
    if (fseek(gDisk, (long)block * (long)BLOCK_SIZE, SEEK_SET) != 0) return -1;
    size_t w = fwrite(in, 1, BLOCK_SIZE, gDisk);
    fflush(gDisk);
    return (w == BLOCK_SIZE) ? 0 : -1;
}

static int load_superblock(void) {
    uint8_t b[BLOCK_SIZE];
    if (read_block(0, b) != 0) return -1;
    memcpy(&gSB, b, sizeof(Superblock));
    if (memcmp(gSB.magic, MAGIC, 4) != 0) {
        gFormatted = 0;
        return -1;
    }
    gFormatted = 1;
    return 0;
}

static int store_superblock(void) {
    uint8_t b[BLOCK_SIZE] = {0};
    memcpy(b, &gSB, sizeof(Superblock));
    return write_block(0, b);
}

// ---------- Bitmap ----------
static int bitmap_read_all(uint8_t **outBuf, uint32_t *outLen) {
    if (!gFormatted) return -1;
    uint32_t len = gSB.bitmapBlocks * BLOCK_SIZE;
    uint8_t *bm = (uint8_t*)calloc(1, len);
    if (!bm) return -1;

    for (uint32_t i = 0; i < gSB.bitmapBlocks; i++) {
        uint8_t blk[BLOCK_SIZE];
        if (read_block(gSB.bitmapStart + i, blk) != 0) { free(bm); return -1; }
        memcpy(bm + i * BLOCK_SIZE, blk, BLOCK_SIZE);
    }
    *outBuf = bm;
    *outLen = len;
    return 0;
}

static int bitmap_write_all(const uint8_t *bm) {
    if (!gFormatted) return -1;
    for (uint32_t i = 0; i < gSB.bitmapBlocks; i++) {
        uint8_t blk[BLOCK_SIZE];
        memcpy(blk, bm + i * BLOCK_SIZE, BLOCK_SIZE);
        if (write_block(gSB.bitmapStart + i, blk) != 0) return -1;
    }
    return 0;
}

static void bm_set(uint8_t *bm, uint32_t block, int used) {
    uint32_t byteIdx = block / 8;
    uint32_t bit = block % 8;
    if (used) bm[byteIdx] |= (uint8_t)(1u << bit);
    else bm[byteIdx] &= (uint8_t)~(1u << bit);
}

static int bm_get(const uint8_t *bm, uint32_t block) {
    uint32_t byteIdx = block / 8;
    uint32_t bit = block % 8;
    return (bm[byteIdx] >> bit) & 1u;
}

// ---------- Table access helpers ----------
static int fnt_read(uint32_t idx, FNTEntry *e) {
    if (idx >= gSB.fntEntries) return -1;
    uint32_t perBlock = 4;
    uint32_t block = gSB.fntStart + (idx / perBlock);
    uint32_t off = (idx % perBlock) * (uint32_t)sizeof(FNTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(e, b + off, sizeof(FNTEntry));
    return 0;
}

static int fnt_write(uint32_t idx, const FNTEntry *e) {
    if (idx >= gSB.fntEntries) return -1;
    uint32_t perBlock = 4;
    uint32_t block = gSB.fntStart + (idx / perBlock);
    uint32_t off = (idx % perBlock) * (uint32_t)sizeof(FNTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(b + off, e, sizeof(FNTEntry));
    return write_block(block, b);
}

static int dabpt_read(uint32_t idx, DABPTEntry *e) {
    if (idx >= gSB.dabptEntries) return -1;
    uint32_t perBlock = 4;
    uint32_t block = gSB.dabptStart + (idx / perBlock);
    uint32_t off = (idx % perBlock) * (uint32_t)sizeof(DABPTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(e, b + off, sizeof(DABPTEntry));
    return 0;
}

static int dabpt_write(uint32_t idx, const DABPTEntry *e) {
    if (idx >= gSB.dabptEntries) return -1;
    uint32_t perBlock = 4;
    uint32_t block = gSB.dabptStart + (idx / perBlock);
    uint32_t off = (idx % perBlock) * (uint32_t)sizeof(DABPTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(b + off, e, sizeof(DABPTEntry));
    return write_block(block, b);
}

static int bpt_read(uint32_t entryIdx, BPTEntry *e) {
    if (entryIdx >= gSB.bptEntries) return -1;
    uint32_t perBlock = bpt_entries_per_block(); // 8
    uint32_t block = gSB.bptStart + (entryIdx / perBlock);
    uint32_t off = (entryIdx % perBlock) * (uint32_t)sizeof(BPTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(e, b + off, sizeof(BPTEntry));
    return 0;
}

static int bpt_write(uint32_t entryIdx, const BPTEntry *e) {
    if (entryIdx >= gSB.bptEntries) return -1;
    uint32_t perBlock = bpt_entries_per_block();
    uint32_t block = gSB.bptStart + (entryIdx / perBlock);
    uint32_t off = (entryIdx % perBlock) * (uint32_t)sizeof(BPTEntry);

    uint8_t b[BLOCK_SIZE];
    if (read_block(block, b) != 0) return -1;
    memcpy(b + off, e, sizeof(BPTEntry));
    return write_block(block, b);
}

static void fnt_set_name(FNTEntry *e, const char *name) {
    memset(e->name, 0, sizeof(e->name));
    strncpy(e->name, name, sizeof(e->name) - 1);
}

static int fnt_name_eq(const FNTEntry *e, const char *name) {
    char tmp[57] = {0};
    memcpy(tmp, e->name, 56);
    return (strncmp(tmp, name, 56) == 0);
}

// ---------- Allocation ----------
static int alloc_fnt(uint32_t *outIdx) {
    for (uint32_t i = 0; i < gSB.fntEntries; i++) {
        FNTEntry e;
        if (fnt_read(i, &e) != 0) return -1;
        if (!e.inUse) { *outIdx = i; return 0; }
    }
    return -1;
}

static int alloc_dabpt(uint32_t *outIdx) {
    for (uint32_t i = 0; i < gSB.dabptEntries; i++) {
        DABPTEntry e;
        if (dabpt_read(i, &e) != 0) return -1;
        if (!e.inUse) { *outIdx = i; return 0; }
    }
    return -1;
}

static int bpt_is_free(const BPTEntry *e) {
    for (int i = 0; i < 8; i++) if (e->ptr[i] != NILPTR) return 0;
    return 1;
}

static int alloc_bpt(uint32_t *outEntryIdx) {
    for (uint32_t i = 0; i < gSB.bptEntries; i++) {
        BPTEntry e;
        if (bpt_read(i, &e) != 0) return -1;
        if (bpt_is_free(&e)) { *outEntryIdx = i; return 0; }
    }
    return -1;
}

static int alloc_data_block(uint32_t *outBlock) {
    uint8_t *bm = NULL;
    uint32_t bmLen = 0;
    if (bitmap_read_all(&bm, &bmLen) != 0) return -1;

    for (uint32_t b = gSB.dataStart; b < gSB.totalBlocks; b++) {
        if (!bm_get(bm, b)) {
            bm_set(bm, b, 1);
            int rc = bitmap_write_all(bm);
            free(bm);
            if (rc != 0) return -1;
            *outBlock = b;
            return 0;
        }
    }
    free(bm);
    return -1;
}

static int free_data_block(uint32_t block) {
    if (block == NILPTR) return 0;
    uint8_t *bm = NULL;
    uint32_t bmLen = 0;
    if (bitmap_read_all(&bm, &bmLen) != 0) return -1;
    if (block < gSB.totalBlocks) bm_set(bm, block, 0);
    int rc = bitmap_write_all(bm);
    free(bm);
    return rc;
}

static int free_bpt_chain(uint32_t head) {
    uint32_t cur = head;
    while (cur != NILPTR) {
        BPTEntry e;
        if (bpt_read(cur, &e) != 0) return -1;

        for (int i = 0; i < 7; i++) {
            if (e.ptr[i] != NILPTR) {
                if (free_data_block(e.ptr[i]) != 0) return -1;
                e.ptr[i] = NILPTR;
            }
        }
        uint32_t next = e.ptr[7];

        for (int i = 0; i < 8; i++) e.ptr[i] = NILPTR;
        if (bpt_write(cur, &e) != 0) return -1;

        cur = next;
    }
    return 0;
}

// ---------- Lookups ----------
static int find_fnt_by_name(const char *name, uint32_t *outIdx, FNTEntry *outEntry) {
    for (uint32_t i = 0; i < gSB.fntEntries; i++) {
        FNTEntry e;
        if (fnt_read(i, &e) != 0) return -1;
        if (e.inUse && fnt_name_eq(&e, name)) {
            if (outIdx) *outIdx = i;
            if (outEntry) *outEntry = e;
            return 0;
        }
    }
    return -1;
}

// ---------- Commands ----------
static void cmd_help(void) {
    puts("Commands:");
    puts("  Createfs <diskfile> <#blocks>");
    puts("  Openfs <diskfile>");
    puts("  Savefs <diskfile_copy>");
    puts("  Formatfs <#filenames> <#DABPTentries>");
    puts("  User <name>");
    puts("  List");
    puts("  Put <hostFilePath> [fsName]");
    puts("  Get <fsName> [hostOutPath]");
    puts("  Rename <old> <new>");
    puts("  Remove <name>");
    puts("  Link <existing> <newname>");
    puts("  Unlink <name>");
    puts("  Quit");
}

static int cmd_createfs(const char *path, uint32_t blocks) {
    FILE *f = fopen(path, "wb+");
    if (!f) { perror("Createfs fopen"); return -1; }

    uint8_t zero[BLOCK_SIZE] = {0};
    for (uint32_t i = 0; i < blocks; i++) {
        if (fwrite(zero, 1, BLOCK_SIZE, f) != BLOCK_SIZE) { perror("Createfs write"); fclose(f); return -1; }
    }
    fflush(f);
    fclose(f);

    printf("Created disk image '%s' with %u blocks (%u bytes)\n", path, blocks, blocks * BLOCK_SIZE);
    return 0;
}

static int cmd_openfs(const char *path) {
    if (gDisk) { fclose(gDisk); gDisk = NULL; }

    gDisk = fopen(path, "rb+");
    if (!gDisk) { perror("Openfs"); return -1; }
    strncpy(gDiskPath, path, sizeof(gDiskPath)-1);
    gDiskPath[sizeof(gDiskPath)-1] = 0;

    if (load_superblock() == 0) {
        printf("Opened formatted FS '%s' (blocks=%u, dataStart=%u)\n", gDiskPath, gSB.totalBlocks, gSB.dataStart);
    } else {
        puts("Opened disk image (unformatted). Run Formatfs after Createfs.");
        gFormatted = 0;
    }
    return 0;
}

static int cmd_savefs(const char *outPath) {
    if (!gDisk) { puts("No disk open."); return -1; }
    fflush(gDisk);

    FILE *in = fopen(gDiskPath, "rb");
    if (!in) { perror("Savefs input"); return -1; }
    FILE *out = fopen(outPath, "wb");
    if (!out) { perror("Savefs output"); fclose(in); return -1; }

    uint8_t buf[4096];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, r, out) != r) { perror("Savefs write"); fclose(in); fclose(out); return -1; }
    }
    fclose(in);
    fclose(out);
    printf("Saved disk image copy to '%s'\n", outPath);
    return 0;
}

static int cmd_formatfs(uint32_t fntEntries, uint32_t dabptEntries) {
    if (!gDisk) { puts("No disk open."); return -1; }

    if (fseek(gDisk, 0, SEEK_END) != 0) { perror("Formatfs fseek"); return -1; }
    long sz = ftell(gDisk);
    if (sz < 0) { perror("Formatfs ftell"); return -1; }
    uint32_t totalBlocks = (uint32_t)(sz / (long)BLOCK_SIZE);

    memset(&gSB, 0, sizeof(gSB));
    memcpy(gSB.magic, MAGIC, 4);
    gSB.totalBlocks = totalBlocks;
    gSB.fntEntries = fntEntries;
    gSB.dabptEntries = dabptEntries;

    gSB.bitmapStart = 1;
    gSB.bitmapBlocks = bitmap_blocks(totalBlocks);

    gSB.fntStart = gSB.bitmapStart + gSB.bitmapBlocks;
    gSB.fntBlocks = fnt_blocks(fntEntries);

    gSB.dabptStart = gSB.fntStart + gSB.fntBlocks;
    gSB.dabptBlocks = dabpt_blocks(dabptEntries);

    // BPT region: allow up to 4 BPT entries per DABPT entry
    uint32_t desiredBptEntries = dabptEntries * 4;
    uint32_t perBlk = bpt_entries_per_block(); // 8
    gSB.bptBlocks = (desiredBptEntries + perBlk - 1) / perBlk;
    gSB.bptEntries = gSB.bptBlocks * perBlk;

    gSB.bptStart = gSB.dabptStart + gSB.dabptBlocks;
    gSB.dataStart = gSB.bptStart + gSB.bptBlocks;

    if (gSB.dataStart >= gSB.totalBlocks) {
        puts("Formatfs failed: disk too small for requested metadata sizes.");
        return -1;
    }

    gFormatted = 1;
    if (store_superblock() != 0) { puts("Failed writing superblock."); return -1; }

    uint32_t bmLen = gSB.bitmapBlocks * BLOCK_SIZE;
    uint8_t *bm = (uint8_t*)calloc(1, bmLen);
    if (!bm) { puts("OOM"); return -1; }

    for (uint32_t b = 0; b < totalBlocks; b++) bm_set(bm, b, 0);
    for (uint32_t b = 0; b < gSB.dataStart; b++) bm_set(bm, b, 1);
    if (bitmap_write_all(bm) != 0) { free(bm); puts("Failed writing bitmap."); return -1; }
    free(bm);

    uint8_t zero[BLOCK_SIZE] = {0};
    for (uint32_t b = 1; b < gSB.dataStart; b++) {
        if (write_block(b, zero) != 0) { puts("Failed zeroing metadata blocks."); return -1; }
    }

    // init BPT region to NILPTRs
    for (uint32_t i = 0; i < gSB.bptEntries; i++) {
        BPTEntry e;
        for (int k = 0; k < 8; k++) e.ptr[k] = NILPTR;
        if (bpt_write(i, &e) != 0) { puts("Failed init BPT."); return -1; }
    }

    printf("Formatted FS. totalBlocks=%u dataStart=%u\n", gSB.totalBlocks, gSB.dataStart);
    return 0;
}

static void cmd_user(const char *name) {
    memset(gUser, 0, sizeof(gUser));
    strncpy(gUser, name, 40);
    printf("Current user: %s\n", gUser);
}

static int cmd_list(void) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    puts("Files:");
    puts("Name                                                     Size   Links   User                                     MTime");
    puts("---------------------------------------------------------------------------------------------------------------------------");

    int any = 0;
    for (uint32_t i = 0; i < gSB.fntEntries; i++) {
        FNTEntry fe;
        if (fnt_read(i, &fe) != 0) return -1;
        if (!fe.inUse) continue;

        DABPTEntry de;
        if (dabpt_read(fe.dabptIndex, &de) != 0) return -1;
        if (!de.inUse) continue;

        char fname[57] = {0};
        memcpy(fname, fe.name, 56);

        char uname[41] = {0};
        memcpy(uname, de.user, 40);

        char tbuf[32];
        time_t tt = (time_t)de.mtime;
        struct tm *tmv = localtime(&tt);
        if (tmv) strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tmv);
        else snprintf(tbuf, sizeof(tbuf), "%" PRIu64, (uint64_t)de.mtime);

        printf("%-56s  %6u  %5u   %-40s  %s\n",
               fname, de.fileSize, (unsigned)de.linkCount, uname, tbuf);
        any = 1;
    }
    if (!any) puts("(no files)");
    return 0;
}

static int cmd_rename(const char *oldn, const char *newn) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    if (find_fnt_by_name(newn, NULL, NULL) == 0) {
        puts("Rename failed: target name already exists.");
        return -1;
    }

    uint32_t idx;
    FNTEntry fe;
    if (find_fnt_by_name(oldn, &idx, &fe) != 0) {
        puts("Rename failed: file not found.");
        return -1;
    }

    fnt_set_name(&fe, newn);
    if (fnt_write(idx, &fe) != 0) { puts("Rename failed: write error."); return -1; }
    puts("Renamed.");
    return 0;
}

static int cmd_unlink_internal(const char *name, int allowRemoveMsg) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    uint32_t fidx;
    FNTEntry fe;
    if (find_fnt_by_name(name, &fidx, &fe) != 0) {
        puts(allowRemoveMsg ? "Remove/Unlink failed: file not found." : "Unlink failed: file not found.");
        return -1;
    }

    DABPTEntry de;
    if (dabpt_read(fe.dabptIndex, &de) != 0) return -1;
    if (!de.inUse) { puts("Corrupt: inode not in use."); return -1; }

    // Remove this directory entry
    uint32_t inode = fe.dabptIndex; // save before zeroing
    memset(&fe, 0, sizeof(fe));
    fe.inUse = 0;
    if (fnt_write(fidx, &fe) != 0) return -1;

    if (de.linkCount > 0) de.linkCount--;

    if (de.linkCount == 0) {
        if (free_bpt_chain(de.bptHead) != 0) { puts("Failed freeing blocks."); return -1; }

        memset(&de, 0, sizeof(de));
        de.inUse = 0;
        if (dabpt_write(inode, &de) != 0) return -1;

        puts("Unlinked last reference: file deleted and space reclaimed.");
    } else {
        if (dabpt_write(inode, &de) != 0) return -1;
        printf("Unlinked. Remaining links: %u\n", (unsigned)de.linkCount);
    }

    return 0;
}

static int cmd_remove(const char *name) { return cmd_unlink_internal(name, 1); }
static int cmd_unlink(const char *name) { return cmd_unlink_internal(name, 0); }

static int cmd_link(const char *existing, const char *newname) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    if (find_fnt_by_name(newname, NULL, NULL) == 0) {
        puts("Link failed: new name already exists.");
        return -1;
    }

    FNTEntry fe;
    if (find_fnt_by_name(existing, NULL, &fe) != 0) {
        puts("Link failed: existing file not found.");
        return -1;
    }

    DABPTEntry de;
    if (dabpt_read(fe.dabptIndex, &de) != 0) return -1;
    if (!de.inUse) { puts("Corrupt: inode not in use."); return -1; }

    uint32_t newFnt;
    if (alloc_fnt(&newFnt) != 0) {
        puts("Link failed: directory full.");
        return -1;
    }

    FNTEntry ne;
    memset(&ne, 0, sizeof(ne));
    fnt_set_name(&ne, newname);
    ne.dabptIndex = fe.dabptIndex;
    ne.inUse = 1;
    if (fnt_write(newFnt, &ne) != 0) return -1;

    de.linkCount++;
    if (dabpt_write(fe.dabptIndex, &de) != 0) return -1;

    puts("Link created.");
    return 0;
}

static int cmd_put(const char *hostPath, const char *fsNameOpt) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    const char *fsName = fsNameOpt ? fsNameOpt : base_name(hostPath);

    if (strlen(fsName) == 0 || strlen(fsName) > 56) {
        puts("Put failed: invalid fsName length (1..56).");
        return -1;
    }

    if (find_fnt_by_name(fsName, NULL, NULL) == 0) {
        puts("Put failed: a file with that name already exists in FS.");
        return -1;
    }

    FILE *in = fopen(hostPath, "rb");
    if (!in) { perror("Put fopen"); return -1; }

    if (fseek(in, 0, SEEK_END) != 0) { perror("Put fseek"); fclose(in); return -1; }
    long sz = ftell(in);
    if (sz < 0) { perror("Put ftell"); fclose(in); return -1; }
    rewind(in);

    uint32_t fntIdx, dabptIdx, bptHead;
    if (alloc_fnt(&fntIdx) != 0) { puts("Put failed: FNT full."); fclose(in); return -1; }
    if (alloc_dabpt(&dabptIdx) != 0) { puts("Put failed: DABPT full."); fclose(in); return -1; }
    if (alloc_bpt(&bptHead) != 0) { puts("Put failed: BPT full."); fclose(in); return -1; }

    uint32_t curBptIdx = bptHead;
    int curSlot = 0;

    BPTEntry curBpt;
    for (int i = 0; i < 8; i++) curBpt.ptr[i] = NILPTR;

    uint8_t buf[BLOCK_SIZE];
    uint32_t bytesRemaining = (uint32_t)sz;
    uint32_t totalWritten = 0;

    while (bytesRemaining > 0) {
        size_t toRead = (bytesRemaining > BLOCK_SIZE) ? BLOCK_SIZE : bytesRemaining;
        size_t r = fread(buf, 1, toRead, in);
        if (r != toRead) {
            puts("Put failed: host read error.");
            fclose(in);
            free_bpt_chain(bptHead);
            return -1;
        }

        uint32_t dataBlk;
        if (alloc_data_block(&dataBlk) != 0) {
            puts("Put failed: disk full (no free data blocks).");
            fclose(in);
            free_bpt_chain(bptHead);
            return -1;
        }

        uint8_t blk[BLOCK_SIZE] = {0};
        memcpy(blk, buf, r);
        if (write_block(dataBlk, blk) != 0) {
            puts("Put failed: disk write error.");
            fclose(in);
            free_data_block(dataBlk);
            free_bpt_chain(bptHead);
            return -1;
        }

        curBpt.ptr[curSlot++] = dataBlk;
        totalWritten += (uint32_t)r;
        bytesRemaining -= (uint32_t)r;

        if (curSlot == 7 && bytesRemaining > 0) {
            uint32_t nextBpt;
            if (alloc_bpt(&nextBpt) != 0) {
                puts("Put failed: BPT chain exhausted.");
                fclose(in);
                free_bpt_chain(bptHead);
                return -1;
            }
            curBpt.ptr[7] = nextBpt;
            if (bpt_write(curBptIdx, &curBpt) != 0) {
                puts("Put failed: BPT write error.");
                fclose(in);
                free_bpt_chain(bptHead);
                return -1;
            }

            curBptIdx = nextBpt;
            for (int i = 0; i < 8; i++) curBpt.ptr[i] = NILPTR;
            curSlot = 0;
        }
    }

    if (bpt_write(curBptIdx, &curBpt) != 0) {
        puts("Put failed: BPT write error.");
        fclose(in);
        free_bpt_chain(bptHead);
        return -1;
    }

    fclose(in);

    DABPTEntry de;
    memset(&de, 0, sizeof(de));
    de.fileSize = totalWritten;
    de.mtime = (uint64_t)time(NULL);
    de.bptHead = bptHead;
    memset(de.user, 0, sizeof(de.user));
    strncpy(de.user, gUser, 40);
    de.linkCount = 1;
    de.inUse = 1;
    if (dabpt_write(dabptIdx, &de) != 0) { puts("Put failed: DABPT write error."); return -1; }

    FNTEntry fe;
    memset(&fe, 0, sizeof(fe));
    fnt_set_name(&fe, fsName);
    fe.dabptIndex = dabptIdx;
    fe.inUse = 1;
    if (fnt_write(fntIdx, &fe) != 0) { puts("Put failed: FNT write error."); return -1; }

    printf("Put ok: '%s' (%u bytes)\n", fsName, totalWritten);
    return 0;
}

static int cmd_get(const char *fsName, const char *hostOutOpt) {
    if (!gFormatted) { puts("FS not formatted."); return -1; }

    FNTEntry fe;
    if (find_fnt_by_name(fsName, NULL, &fe) != 0) {
        puts("Get failed: file not found.");
        return -1;
    }

    DABPTEntry de;
    if (dabpt_read(fe.dabptIndex, &de) != 0) return -1;
    if (!de.inUse) { puts("Corrupt: inode not in use."); return -1; }

    const char *outPath = hostOutOpt ? hostOutOpt : fsName;
    FILE *out = fopen(outPath, "wb");
    if (!out) { perror("Get fopen"); return -1; }

    uint32_t remaining = de.fileSize;
    uint32_t cur = de.bptHead;

    while (remaining > 0 && cur != NILPTR) {
        BPTEntry be;
        if (bpt_read(cur, &be) != 0) { fclose(out); return -1; }

        for (int i = 0; i < 7 && remaining > 0; i++) {
            if (be.ptr[i] == NILPTR) break;

            uint8_t blk[BLOCK_SIZE];
            if (read_block(be.ptr[i], blk) != 0) { fclose(out); return -1; }
            uint32_t toWrite = (remaining > BLOCK_SIZE) ? BLOCK_SIZE : remaining;

            if (fwrite(blk, 1, toWrite, out) != toWrite) { perror("Get write"); fclose(out); return -1; }
            remaining -= toWrite;
        }
        cur = be.ptr[7];
    }

    fclose(out);

    if (remaining != 0) {
        puts("Get warning: ran out of pointers before reading full file (corruption).");
        return -1;
    }
    printf("Get ok: wrote '%s' (%u bytes)\n", outPath, de.fileSize);
    return 0;
}

// ---------- Main loop ----------
int main(void) {
    puts("FS - Mini File System (CSE 3320)");
    puts("Type 'Help' for commands.");

    char line[MAX_LINE];

    while (1) {
        printf("FS> ");
        if (!fgets(line, sizeof(line), stdin)) break;
        trim_newline(line);
        if (line[0] == 0) continue;

        char *tok[MAX_TOKENS] = {0};
        int nt = tokenize(line, tok, MAX_TOKENS);
        if (nt == 0) continue;

        char cmd[32] = {0};
        strncpy(cmd, tok[0], sizeof(cmd)-1);
        for (char *p = cmd; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');

        if (strcmp(cmd, "help") == 0) {
            cmd_help();
        } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
            break;
        } else if (strcmp(cmd, "createfs") == 0) {
            if (nt != 3) { puts("Usage: Createfs <diskfile> <#blocks>"); continue; }
            uint32_t blocks = (uint32_t)strtoul(tok[2], NULL, 10);
            cmd_createfs(tok[1], blocks);
        } else if (strcmp(cmd, "openfs") == 0) {
            if (nt != 2) { puts("Usage: Openfs <diskfile>"); continue; }
            cmd_openfs(tok[1]);
        } else if (strcmp(cmd, "savefs") == 0) {
            if (nt != 2) { puts("Usage: Savefs <diskfile_copy>"); continue; }
            cmd_savefs(tok[1]);
        } else if (strcmp(cmd, "formatfs") == 0) {
            if (nt != 3) { puts("Usage: Formatfs <#filenames> <#DABPTentries>"); continue; }
            uint32_t fntE = (uint32_t)strtoul(tok[1], NULL, 10);
            uint32_t dabE = (uint32_t)strtoul(tok[2], NULL, 10);
            cmd_formatfs(fntE, dabE);
        } else if (strcmp(cmd, "user") == 0) {
            if (nt != 2) { puts("Usage: User <name>"); continue; }
            cmd_user(tok[1]);
        } else if (strcmp(cmd, "list") == 0) {
            cmd_list();
        } else if (strcmp(cmd, "put") == 0) {
            if (nt != 2 && nt != 3) { puts("Usage: Put <hostFilePath> [fsName]"); continue; }
            cmd_put(tok[1], (nt == 3) ? tok[2] : NULL);
        } else if (strcmp(cmd, "get") == 0) {
            if (nt != 2 && nt != 3) { puts("Usage: Get <fsName> [hostOutPath]"); continue; }
            cmd_get(tok[1], (nt == 3) ? tok[2] : NULL);
        } else if (strcmp(cmd, "rename") == 0) {
            if (nt != 3) { puts("Usage: Rename <old> <new>"); continue; }
            cmd_rename(tok[1], tok[2]);
        } else if (strcmp(cmd, "remove") == 0) {
            if (nt != 2) { puts("Usage: Remove <name>"); continue; }
            cmd_remove(tok[1]);
        } else if (strcmp(cmd, "unlink") == 0) {
            if (nt != 2) { puts("Usage: Unlink <name>"); continue; }
            cmd_unlink(tok[1]);
        } else if (strcmp(cmd, "link") == 0) {
            if (nt != 3) { puts("Usage: Link <existing> <newname>"); continue; }
            cmd_link(tok[1], tok[2]);
        } else {
            puts("Unknown command. Type Help.");
        }
    }

    if (gDisk) fclose(gDisk);
    puts("Bye.");
    return 0;
}