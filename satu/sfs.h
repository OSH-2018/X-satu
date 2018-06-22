/*
 * The little filesystem (adapted)
 *
 * Copyright (c) 2017 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SFS_H
#define SFS_H

#include <stdint.h>
#include <stdbool.h>


/// Version info ///

// Software library version
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define SFS_VERSION 0x00010004
#define SFS_VERSION_MAJOR (0xffff & (SFS_VERSION >> 16))
#define SFS_VERSION_MINOR (0xffff & (SFS_VERSION >>  0))

// Version of On-disk data structures
// Major (top-nibble), incremented on backwards incompatible changes
// Minor (bottom-nibble), incremented on feature additions
#define SFS_DISK_VERSION 0x00010001
#define SFS_DISK_VERSION_MAJOR (0xffff & (SFS_DISK_VERSION >> 16))
#define SFS_DISK_VERSION_MINOR (0xffff & (SFS_DISK_VERSION >>  0))


/// Definitions ///

// Type definitions
typedef uint32_t sfs_size_t;
typedef uint32_t sfs_off_t;

typedef int32_t  sfs_ssize_t;
typedef int32_t  sfs_soff_t;

typedef uint32_t sfs_block_t;

#ifndef SFS_NET_ADDR_TYPE
typedef void* sfs_addr_t;
#else
typedef SFS_NET_ADDR_TYPE sfs_addr_t;
#endif

// Max name size in bytes
#ifndef SFS_NAME_MAX
#define SFS_NAME_MAX 255
#endif

// Max network connection slots
#ifndef SFS_CONN_MAX
#define SFS_CONN_MAX 5
#endif

// Possible error codes, these are negative to allow
// valid positive return values
enum sfs_error {
    SFS_ERR_OK       = 0,    // No error
    SFS_ERR_IO       = -5,   // Error during device operation
    SFS_ERR_CORRUPT  = -52,  // Corrupted
    SFS_ERR_NOENT    = -2,   // No directory entry
    SFS_ERR_EXIST    = -17,  // Entry already exists
    SFS_ERR_NOTDIR   = -20,  // Entry is not a dir
    SFS_ERR_ISDIR    = -21,  // Entry is a dir
    SFS_ERR_NOTEMPTY = -39,  // Dir is not empty
    SFS_ERR_BADF     = -9,   // Bad file number
    SFS_ERR_INVAL    = -22,  // Invalid parameter
    SFS_ERR_NOSPC    = -28,  // No space left on device
    SFS_ERR_NOMEM    = -12,  // No more memory available
};

// File types
enum sfs_type {
    SFS_TYPE_REG        = 0x11,
    SFS_TYPE_STR        = 0x12,
    SFS_TYPE_MSG        = 0x13,
    SFS_TYPE_DIR        = 0x22,
    SFS_TYPE_SUPERBLOCK = 0x2e,
};

// File open flags
enum sfs_open_flags {
    // open flags
    SFS_O_RDONLY = 1,        // Open a file as read only
    SFS_O_WRONLY = 2,        // Open a file as write only
    SFS_O_RDWR   = 3,        // Open a file as read and write
    SFS_O_CREAT  = 0x0100,   // Create a file if it does not exist
    SFS_O_EXCL   = 0x0200,   // Fail if a file already exists
    SFS_O_TRUNC  = 0x0400,   // Truncate the existing file to zero size
    SFS_O_APPEND = 0x0800,   // Move to end of file on every write

    // internally used flags
    SFS_F_DIRTY   = 0x10000, // File does not match storage
    SFS_F_WRITING = 0x20000, // File has been written since last flush
    SFS_F_READING = 0x40000, // File has been read since last flush
    SFS_F_ERRED   = 0x80000, // An error occured during write
};

// File seek flags
enum sfs_whence_flags {
    SFS_SEEK_SET = 0,   // Seek relative to an absolute position
    SFS_SEEK_CUR = 1,   // Seek relative to the current file position
    SFS_SEEK_END = 2,   // Seek relative to the end of the file
};


// Configuration provided during initialization of the littlefs
struct sfs_config {
    // Opaque user provided context that can be used to pass
    // information to the block device operations
    void *context;

    // Read a region in a block. Negative error codes are propogated
    // to the user.
    int (*read)(const struct sfs_config *c, sfs_block_t block,
            sfs_off_t off, void *buffer, sfs_size_t size);

    // Program a region in a block. The block must have previously
    // been erased. Negative error codes are propogated to the user.
    // May return SFS_ERR_CORRUPT if the block should be considered bad.
    int (*prog)(const struct sfs_config *c, sfs_block_t block,
            sfs_off_t off, const void *buffer, sfs_size_t size);

    // Erase a block. A block must be erased before being programmed.
    // The state of an erased block is undefined. Negative error codes
    // are propogated to the user.
    // May return SFS_ERR_CORRUPT if the block should be considered bad.
    int (*erase)(const struct sfs_config *c, sfs_block_t block);

    // Sync the state of the underlying block device. Negative error codes
    // are propogated to the user.
    int (*sync)(const struct sfs_config *c);

    // Connect to a server. One should connect to servers according to
    // some order. Negative error codes are propogated to the user.
    int (*connect)(const struct sfs_config *c, sfs_addr_t addr);

    // Send out data packets to a specific network address. Negative
    // error codes are propogated to the user.
    int (*send)(const struct sfs_config *c,
                sfs_addr_t addr,
                const void *buffer,
                sfs_size_t size);

    // Receive data packets from a specific network address. Negative
    // error codes are propogated to the user.
    int (*recv)(const struct sfs_config *c,
                sfs_addr_t addr,
                void *buffer,
                sfs_size_t size);

    // Minimum size of a block read. This determines the size of read buffers.
    // This may be larger than the physical read size to improve performance
    // by caching more of the block device.
    sfs_size_t read_size;

    // Minimum size of a block program. This determines the size of program
    // buffers. This may be larger than the physical program size to improve
    // performance by caching more of the block device.
    // Must be a multiple of the read size.
    sfs_size_t prog_size;

    // Size of an erasable block. This does not impact ram consumption and
    // may be larger than the physical erase size. However, this should be
    // kept small as each file currently takes up an entire block.
    // Must be a multiple of the program size.
    sfs_size_t block_size;

    // Number of erasable blocks on the device.
    sfs_size_t block_count;

    // Number of blocks to lookahead during block allocation. A larger
    // lookahead reduces the number of passes required to allocate a block.
    // The lookahead buffer requires only 1 bit per block so it can be quite
    // large with little ram impact. Should be a multiple of 32.
    sfs_size_t lookahead;

    // Optional, statically allocated read buffer. Must be read sized.
    void *read_buffer;

    // Optional, statically allocated program buffer. Must be program sized.
    void *prog_buffer;

    // Optional, statically allocated lookahead buffer. Must be 1 bit per
    // lookahead block.
    void *lookahead_buffer;

    // Optional, statically allocated buffer for files. Must be program sized.
    // If enabled, only one file may be opened at a time.
    void *file_buffer;
};


// File info structure
struct sfs_info {
    // Type of the file, either SFS_TYPE_REG or SFS_TYPE_DIR
    uint8_t type;

    // Size of the file, only valid for REG files
    sfs_size_t size;

    // Name of the file stored as a null-terminated string
    char name[SFS_NAME_MAX+1];
};


/// littlefs data structures ///
typedef struct sfs_entry {
    sfs_off_t off;

    struct sfs_disk_entry {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        union {
            struct {
                sfs_block_t head;
                sfs_size_t size;
            } file;
            sfs_block_t dir[2];
        } u;
    } d;
} sfs_entry_t;

typedef struct sfs_cache {
    sfs_block_t block;
    sfs_off_t off;
    uint8_t *buffer;
} sfs_cache_t;

typedef struct sfs_file {
    struct sfs_file *next;
    sfs_block_t pair[2];
    sfs_off_t poff;

    sfs_block_t head;
    sfs_size_t size;

    uint32_t flags;
    sfs_off_t pos;
    sfs_block_t block;
    sfs_off_t off;
    sfs_cache_t cache;
} sfs_file_t;

typedef struct sfs_dir {
    struct sfs_dir *next;
    sfs_block_t pair[2];
    sfs_off_t off;

    sfs_block_t head[2];
    sfs_off_t pos;

    struct sfs_disk_dir {
        uint32_t rev;
        sfs_size_t size;
        sfs_block_t tail[2];
    } d;
} sfs_dir_t;

typedef struct sfs_superblock {
    sfs_off_t off;

    struct sfs_disk_superblock {
        uint8_t type;
        uint8_t elen;
        uint8_t alen;
        uint8_t nlen;
        sfs_block_t root[2];
        uint32_t block_size;
        uint32_t block_count;
        uint32_t version;
        char magic[8];
    } d;
} sfs_superblock_t;

typedef struct sfs_free {
    sfs_block_t off;
    sfs_block_t size;
    sfs_block_t i;
    sfs_block_t ack;
    uint32_t *buffer;
} sfs_free_t;

// The littlefs type
typedef struct sfs {
    const struct sfs_config *cfg;

    sfs_block_t root[2];
    sfs_file_t *files;
    sfs_dir_t *dirs;

    sfs_cache_t rcache;
    sfs_cache_t pcache;

    sfs_free_t free;
    bool deorphaned;
} sfs_t;


/// Filesystem functions ///

// Format a block device with the littlefs
//
// Requires a littlefs object and config struct. This clobbers the littlefs
// object, and does not leave the filesystem mounted.
//
// Returns a negative error code on failure.
int sfs_format(sfs_t *sfs, const struct sfs_config *config);

// Mounts a littlefs
//
// Requires a littlefs object and config struct. Multiple filesystems
// may be mounted simultaneously with multiple littlefs objects. Both
// sfs and config must be allocated while mounted.
//
// Returns a negative error code on failure.
int sfs_mount(sfs_t *sfs, const struct sfs_config *config);

// Unmounts a littlefs
//
// Does nothing besides releasing any allocated resources.
// Returns a negative error code on failure.
int sfs_unmount(sfs_t *sfs);

/// General operations ///

// Removes a file or directory
//
// If removing a directory, the directory must be empty.
// Returns a negative error code on failure.
int sfs_remove(sfs_t *sfs, const char *path);

// Rename or move a file or directory
//
// If the destination exists, it must match the source in type.
// If the destination is a directory, the directory must be empty.
//
// Returns a negative error code on failure.
int sfs_rename(sfs_t *sfs, const char *oldpath, const char *newpath);

// Find info about a file or directory
//
// Fills out the info structure, based on the specified file or directory.
// Returns a negative error code on failure.
int sfs_stat(sfs_t *sfs, const char *path, struct sfs_info *info);


/// File operations ///

// Open a file
//
// The mode that the file is opened in is determined
// by the flags, which are values from the enum sfs_open_flags
// that are bitwise-ored together.
//
// Returns a negative error code on failure.
int sfs_file_open(sfs_t *sfs, sfs_file_t *file,
        const char *path, int flags);

// Close a file
//
// Any pending writes are written out to storage as though
// sync had been called and releases any allocated resources.
//
// Returns a negative error code on failure.
int sfs_file_close(sfs_t *sfs, sfs_file_t *file);

// Synchronize a file on storage
//
// Any pending writes are written out to storage.
// Returns a negative error code on failure.
int sfs_file_sync(sfs_t *sfs, sfs_file_t *file);

// Read data from file
//
// Takes a buffer and size indicating where to store the read data.
// Returns the number of bytes read, or a negative error code on failure.
sfs_ssize_t sfs_file_read(sfs_t *sfs, sfs_file_t *file,
        void *buffer, sfs_size_t size);

// Write data to file
//
// Takes a buffer and size indicating the data to write. The file will not
// actually be updated on the storage until either sync or close is called.
//
// Returns the number of bytes written, or a negative error code on failure.
sfs_ssize_t sfs_file_write(sfs_t *sfs, sfs_file_t *file,
        const void *buffer, sfs_size_t size);

// Change the position of the file
//
// The change in position is determined by the offset and whence flag.
// Returns the old position of the file, or a negative error code on failure.
sfs_soff_t sfs_file_seek(sfs_t *sfs, sfs_file_t *file,
        sfs_soff_t off, int whence);

// Truncates the size of the file to the specified size
//
// Returns a negative error code on failure.
int sfs_file_truncate(sfs_t *sfs, sfs_file_t *file, sfs_off_t size);

// Return the position of the file
//
// Equivalent to sfs_file_seek(sfs, file, 0, SFS_SEEK_CUR)
// Returns the position of the file, or a negative error code on failure.
sfs_soff_t sfs_file_tell(sfs_t *sfs, sfs_file_t *file);

// Change the position of the file to the beginning of the file
//
// Equivalent to sfs_file_seek(sfs, file, 0, SFS_SEEK_CUR)
// Returns a negative error code on failure.
int sfs_file_rewind(sfs_t *sfs, sfs_file_t *file);

// Return the size of the file
//
// Similar to sfs_file_seek(sfs, file, 0, SFS_SEEK_END)
// Returns the size of the file, or a negative error code on failure.
sfs_soff_t sfs_file_size(sfs_t *sfs, sfs_file_t *file);


/// Directory operations ///

// Create a directory
//
// Returns a negative error code on failure.
int sfs_mkdir(sfs_t *sfs, const char *path);

// Open a directory
//
// Once open a directory can be used with read to iterate over files.
// Returns a negative error code on failure.
int sfs_dir_open(sfs_t *sfs, sfs_dir_t *dir, const char *path);

// Close a directory
//
// Releases any allocated resources.
// Returns a negative error code on failure.
int sfs_dir_close(sfs_t *sfs, sfs_dir_t *dir);

// Read an entry in the directory
//
// Fills out the info structure, based on the specified file or directory.
// Returns a negative error code on failure.
int sfs_dir_read(sfs_t *sfs, sfs_dir_t *dir, struct sfs_info *info);

// Change the position of the directory
//
// The new off must be a value previous returned from tell and specifies
// an absolute offset in the directory seek.
//
// Returns a negative error code on failure.
int sfs_dir_seek(sfs_t *sfs, sfs_dir_t *dir, sfs_off_t off);

// Return the position of the directory
//
// The returned offset is only meant to be consumed by seek and may not make
// sense, but does indicate the current position in the directory iteration.
//
// Returns the position of the directory, or a negative error code on failure.
sfs_soff_t sfs_dir_tell(sfs_t *sfs, sfs_dir_t *dir);

// Change the position of the directory to the beginning of the directory
//
// Returns a negative error code on failure.
int sfs_dir_rewind(sfs_t *sfs, sfs_dir_t *dir);


/// Miscellaneous littlefs specific operations ///

// Traverse through all blocks in use by the filesystem
//
// The provided callback will be called with each block address that is
// currently in use by the filesystem. This can be used to determine which
// blocks are in use or how much of the storage is available.
//
// Returns a negative error code on failure.
int sfs_traverse(sfs_t *sfs, int (*cb)(void*, sfs_block_t), void *data);

// Prunes any recoverable errors that may have occured in the filesystem
//
// Not needed to be called by user unless an operation is interrupted
// but the filesystem is still mounted. This is already called on first
// allocation.
//
// Returns a negative error code on failure.
int sfs_deorphan(sfs_t *sfs);


#endif
