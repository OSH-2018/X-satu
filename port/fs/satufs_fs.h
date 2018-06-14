#pragma once

#include "vfs.h"
#include "sfs.h"
#include "mtd.h"
#include "mutex.h"

/// satufs descriptor for vfs integration
typedef struct {
    sfs_t         fs;           // satufs descriptor
    sfs_config_t  config;       // satufs config
    mtd_dev_t    *dev;          // MTD device
    mutex_t       lock;         // mutex
} satufs_desc_t;

extern const vfs_file_system_t satufs_file_system;
