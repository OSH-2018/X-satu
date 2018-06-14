#include <stdio.h>
#include <errno.h>
#include "satufs_fs.h"

#define ENABLE_DEBUG 1
#include <debug.h>

static int prepare(satufs_desc_t *fs)
{
    mutex_init(&fs->lock);
    mutex_lock(&fs->lock);

    return mtd_init(fs->dev);
}

static int _format(vfs_mount_t *mountp)
{
    satufs_desc_t *fs = mountp->private_data;
    int ret = prepare(fs);

    if (ret) {
        return -ENODEV;
    }
    mutex_unlock(&fs->lock);
    return 0;
}

static const vfs_file_system_ops_t satufs_fs_ops = {
    .format = _format
};

static const vfs_file_ops_t satufs_file_ops;

static const vfs_dir_ops_t satufs_dir_ops;

const vfs_file_system_t satufs_file_system = {
    .fs_op = &satufs_fs_ops,
    .f_op = &satufs_file_ops,
    .d_op = &satufs_dir_ops
};
