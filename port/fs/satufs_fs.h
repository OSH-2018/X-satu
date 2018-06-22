/*
 * Copyright (C) 2017 OTA keys S.A.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @defgroup    sys_satufs  satufs integration
 * @ingroup     pkg_satufs
 * @brief       RIOT integration of satufs
 *
 * @{
 *
 * @file
 * @brief       satufs integration with vfs
 *
 * @author      Vincent Dupont <vincent@otakeys.com>
 */

#ifndef FS_SATUFS_FS_H
#define FS_SATUFS_FS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "vfs.h"
#include "sfs.h"
#include "mtd.h"
#include "mutex.h"
#include "net/sock/udp.h"

#if VFS_FILE_BUFFER_SIZE < 52
#error "VFS_FILE_BUFFER_SIZE is too small, at least 52 bytes is required"
#endif

#if VFS_DIR_BUFFER_SIZE < 44
#error "VFS_DIR_BUFFER_SIZE is too small, at least 44 bytes is required"
#endif

/**
 * @name    satufs configuration
 * @{
 */
#ifndef SATUFS_LOOKAHEAD_SIZE
/** Default lookahead size */
#define SATUFS_LOOKAHEAD_SIZE     (128)
#endif

#ifndef SATUFS_FILE_BUFFER_SIZE
/** File buffer size, if 0, dynamic allocation is used.
 * If set, only one file can be used at a time, must be program size (mtd page size
 * is used internally as program size) */
#define SATUFS_FILE_BUFFER_SIZE   (0)
#endif

#ifndef SATUFS_READ_BUFFER_SIZE
/** Read buffer size, if 0, dynamic allocation is used.
 * If set, it must be read size (mtd page size is used internally as read size) */
#define SATUFS_READ_BUFFER_SIZE   (0)
#endif

#ifndef SATUFS_PROG_BUFFER_SIZE
/** Prog buffer size, if 0, dynamic allocation is used.
 * If set, it must be program size */
#define SATUFS_PROG_BUFFER_SIZE   (0)
#endif

#ifndef SATUFS_CONN_MAX
/** How many connections at the same time? */
#define SATUFS_CONN_MAX (5)
#endif
/** @} */

/**
 * @brief   satufs descriptor for vfs integration
 */
typedef struct {
    sfs_t fs;                   /**< satufs descriptor */
    struct sfs_config config;   /**< satufs config */
    mtd_dev_t *dev;             /**< mtd device to use */
    mutex_t lock;               /**< mutex */
    /** first block number to use,
     * total number of block is defined in @p config.
     * if set to 0, the total number of sectors from the mtd is used */
    uint32_t base_addr;
#if SATUFS_FILE_BUFFER_SIZE || DOXYGEN
    /** file buffer to use internally if SATUFS_FILE_BUFFER_SIZE is set */
    uint8_t file_buf[SATUFS_FILE_BUFFER_SIZE];
#endif
#if SATUFS_READ_BUFFER_SIZE || DOXYGEN
    /** read buffer to use internally if SATUFS_READ_BUFFER_SIZE is set */
    uint8_t read_buf[SATUFS_READ_BUFFER_SIZE];
#endif
#if SATUFS_PROG_BUFFER_SIZE || DOXYGEN
    /** prog buffer to use internally if SATUFS_PROG_BUFFER_SIZE is set */
    uint8_t prog_buf[SATUFS_PROG_BUFFER_SIZE];
#endif
    /** lookahead buffer to use internally */
    uint8_t lookahead_buf[SATUFS_LOOKAHEAD_SIZE / 8];
    /** connections */
    short n_conn;
    sock_udp_t conn[SATUFS_CONN_MAX];
} satufs_desc_t;

/** The satufs vfs driver */
extern const vfs_file_system_t satufs_file_system;

#ifdef __cplusplus
}
#endif

#endif /* FS_SATUFS_FS_H */
/** @} */
