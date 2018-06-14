#pragma once

#include "vfs.h"
#include "sfs.h"
#include "mtd.h"
#include "mutex.h"

typedef struct {
    mtd_dev_t *dev;
    mutex_t lock;
} satufs_desc_t;

extern const vfs_file_system_t satufs_file_system;
