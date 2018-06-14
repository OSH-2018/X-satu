#include <stdio.h>
#include <errno.h>
#include "satufs_fs.h"

#define ENABLE_DEBUG 1
#include <debug.h>

static int _format(vfs_mount_t *mountp)
{
    (void) mountp;
    return -ENOTSUP;
}

static int _mount(vfs_mount_t *mountp)
{
    (void) mountp;
    return -ENOTSUP;
}

static int _umount(vfs_mount_t *mountp)
{
    (void) mountp;
    return -ENOTSUP;
}

static int _unlink(vfs_mount_t *mountp, const char *name)
{
    (void) mountp;
    (void) name;
    return -ENOTSUP;
}

static int _mkdir(vfs_mount_t *mountp, const char *name, mode_t mode)
{
    (void) mountp;
    (void) name;
    (void) mode;
    return -ENOTSUP;
}

static int _rmdir(vfs_mount_t *mountp, const char *name)
{
    (void) mountp;
    (void) name;
    return -ENOTSUP;
}

static int _rename(vfs_mount_t *mountp, const char *from_path, const char *to_path)
{
    (void) mountp;
    (void) from_path;
    (void) to_path;
    return -ENOTSUP;
}

static int _stat(vfs_mount_t *mountp,
                 const char *restrict path,
                 struct stat *restrict buf)
{
    (void) mountp;
    (void) path;
    (void) buf;
    return -ENOTSUP;
}

static int _statvfs(vfs_mount_t *mountp,
                    const char *restrict path,
                    struct statvfs *restrict buf)
{
    (void) mountp;
    (void) path;
    (void) buf;
    return -ENOTSUP;
}

static int _open(vfs_file_t *filp, const char *name, int flags,
                 mode_t mode, const char *abs_path)
{
    (void) filp;
    (void) name;
    (void) flags;
    (void) mode;
    (void) abs_path;
    return -ENOTSUP;
}

static int _close(vfs_file_t *filp)
{
    (void) filp;
    return -ENOTSUP;
}

static ssize_t _read(vfs_file_t *filp, void *dest, size_t nbytes)
{
    (void) filp;
    (void) dest;
    (void) nbytes;
    return -ENOTSUP;
}

static ssize_t _write(vfs_file_t *filp, const void *src, size_t nbytes)
{
    (void) filp;
    (void) src;
    (void) nbytes;
    return -ENOTSUP;
}

static off_t _lseek(vfs_file_t *filp, off_t off, int whence)
{
    (void) filp;
    (void) off;
    (void) whence;
    return -ENOTSUP;
}

static int _fcntl(vfs_file_t *filp, int cmd, int arg)
{
    (void) filp;
    (void) cmd;
    (void) arg;
    return -ENOTSUP;
}

static int _fstat(vfs_file_t *filp, struct stat *buf)
{
    (void) filp;
    (void) buf;
    return -ENOTSUP;
}

static int _opendir(vfs_DIR *dirp, const char *dirname, const char *abs_path)
{
    (void) dirp;
    (void) dirname;
    (void) abs_path;
    return -ENOTSUP;
}

static int _readdir(vfs_DIR *dirp, vfs_dirent_t *entry)
{
    (void) dirp;
    (void) entry;
    return -ENOTSUP;
}

static int _closedir(vfs_DIR *dirp)
{
    (void) dirp;
    return -ENOTSUP;
}

static const vfs_file_system_ops_t satufs_fs_ops = {
    .format = _format,
    .mount = _mount,
    .umount = _umount,
    .unlink = _unlink,
    .mkdir = _mkdir,
    .rmdir = _rmdir,
    .rename = _rename,
    .stat = _stat,
    .statvfs = _statvfs
};

static const vfs_file_ops_t satufs_file_ops = {
    .open = _open,
    .close = _close,
    .read = _read,
    .write = _write,
    .lseek = _lseek,
    .fcntl = _fcntl,
    .fstat = _fstat
};

static const vfs_dir_ops_t satufs_dir_ops = {
    .opendir = _opendir,
    .readdir = _readdir,
    .closedir = _closedir
};

const vfs_file_system_t satufs_file_system = {
    .fs_op = &satufs_fs_ops,
    .f_op = &satufs_file_ops,
    .d_op = &satufs_dir_ops
};
