/*
 * Copyright (C) 2017 OTA keys S.A.
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_satufs
 * @{
 *
 * @file
 * @brief       satufs integration with vfs
 *
 * @author      Vincent Dupont <vincent@otakeys.com>
 *
 * @}
 */


#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "fs/satufs_fs.h"
#include "net/sock/udp.h"

#include "kernel_defines.h"

#define ENABLE_DEBUG (1)
#include <debug.h>

static int satufs_err_to_errno(ssize_t err)
{
    switch (err) {
    case SFS_ERR_OK:
        return 0;
    case SFS_ERR_IO:
        return -EIO;
    case SFS_ERR_CORRUPT:
        return -ENODEV;
    case SFS_ERR_NOENT:
        return -ENOENT;
    case SFS_ERR_EXIST:
        return -EEXIST;
    case SFS_ERR_NOTDIR:
        return -ENOTDIR;
    case SFS_ERR_ISDIR:
        return -EISDIR;
    case SFS_ERR_NOTEMPTY:
        return -ENOTEMPTY;
    case SFS_ERR_BADF:
        return -EBADF;
    case SFS_ERR_INVAL:
        return -EINVAL;
    case SFS_ERR_NOSPC:
        return -ENOSPC;
    case SFS_ERR_NOMEM:
        return -ENOMEM;
    default:
        return err;
    }
}

static int _dev_read(const struct sfs_config *c, sfs_block_t block,
                 sfs_off_t off, void *buffer, sfs_size_t size)
{
    satufs_desc_t *fs = c->context;
    mtd_dev_t *mtd = fs->dev;

    DEBUG("sfs_read: c=%p, block=%" PRIu32 ", off=%" PRIu32 ", buf=%p, size=%" PRIu32 "\n",
          (void *)c, block, off, buffer, size);

    int ret = mtd_read(mtd, buffer, ((fs->base_addr + block) * c->block_size) + off, size);
    if (ret >= 0) {
        return 0;
    }

    return ret;
}

static int _dev_write(const struct sfs_config *c, sfs_block_t block,
                  sfs_off_t off, const void *buffer, sfs_size_t size)
{
    satufs_desc_t *fs = c->context;
    mtd_dev_t *mtd = fs->dev;

    DEBUG("sfs_write: c=%p, block=%" PRIu32 ", off=%" PRIu32 ", buf=%p, size=%" PRIu32 "\n",
          (void *)c, block, off, buffer, size);

    const uint8_t *buf = buffer;
    uint32_t addr = ((fs->base_addr + block) * c->block_size) + off;
    for (const uint8_t *part = buf; part < buf + size; part += c->prog_size,
         addr += c->prog_size) {
        int ret = mtd_write(mtd, part, addr, c->prog_size);
        if (ret < 0) {
            return ret;
        }
        else if ((unsigned)ret != c->prog_size) {
            return -EIO;
        }
    }

    return 0;
}

static int _dev_erase(const struct sfs_config *c, sfs_block_t block)
{
    satufs_desc_t *fs = c->context;
    mtd_dev_t *mtd = fs->dev;

    DEBUG("sfs_erase: c=%p, block=%" PRIu32 "\n", (void *)c, block);

    int ret = mtd_erase(mtd, ((fs->base_addr + block) * c->block_size), c->block_size);
    if (ret >= 0) {
        return 0;
    }

    return ret;
}

static int _dev_sync(const struct sfs_config *c)
{
    (void)c;

    return 0;
}

static int
_dev_connect(const struct sfs_config *c,
             const char *ipv6_addr,
             uint16_t port,
             sfs_addr_t *addr)
{
    satufs_desc_t *fs = c->context;
    int id = fs->n_conn;
    int res;
    sock_udp_ep_t remote;

    remote.family = AF_INET6;
    remote.netif = SOCK_ADDR_ANY_NETIF;
    remote.port = port;
    if (ipv6_addr_from_str((ipv6_addr_t*)&remote.addr, ipv6_addr) == NULL) {
        DEBUG("Failed to parse address\n");
        return -EINVAL;
    }

#if ENABLE_DEBUG
    DEBUG("is this loopback? %d\n", ipv6_addr_is_loopback((ipv6_addr_t *)&remote.addr));
#endif

    if (id >= SATUFS_CONN_MAX) {
        DEBUG("satufs_connect: overflow\n");
        return -EINVAL;
    }

    res = sock_udp_create(&fs->conn[id], NULL, &remote, 0);
    if (!res) {
        fs->n_conn++;
        DEBUG("satufs_connect: success addr=%p\n", (void*)&fs->conn[id]);
    } else {
        DEBUG("satufs_connect: failed with %s\n", strerror(-res));
    }

    *addr = &fs->conn[id]; // typeof(addr) == sock_udp_t*

    return res;
}

static int
_dev_send(const struct sfs_config *c,
          sfs_addr_t addr,
          const void *buffer,
          sfs_size_t size)
{
    (void) c;

    sock_udp_t *sock = addr;
    sock_udp_ep_t remote;
    char buf[256];

    sock_udp_get_remote(sock, &remote);
    printf("remote.port=%d\n", remote.port);

    ipv6_addr_to_str(buf, (ipv6_addr_t *)&remote.addr, remote.port);
    printf("remote.addr=%s\n", buf);

    return sock_udp_send(addr, buffer, size, NULL);
}

static int
_dev_recv(const struct sfs_config *c,
          sfs_addr_t addr,
          void *buffer,
          sfs_size_t size)
{
    (void) c;
    (void) addr;
    (void) buffer;
    (void) size;

    return 0;
}

static int prepare(satufs_desc_t *fs)
{
    mutex_init(&fs->lock);
    mutex_lock(&fs->lock);

    memset(&fs->fs, 0, sizeof(fs->fs));

    if (!fs->config.block_count) {
        fs->config.block_count = fs->dev->sector_count - fs->base_addr;
    }
    if (!fs->config.block_size) {
        fs->config.block_size = fs->dev->page_size * fs->dev->pages_per_sector;
    }
    if (!fs->config.prog_size) {
        fs->config.prog_size = fs->dev->page_size;
    }
    if (!fs->config.read_size) {
        fs->config.read_size = fs->dev->page_size;
    }
    fs->config.lookahead = SATUFS_LOOKAHEAD_SIZE;
    fs->config.lookahead_buffer = fs->lookahead_buf;
    fs->config.context = fs;
    fs->config.read = _dev_read;
    fs->config.prog = _dev_write;
    fs->config.erase = _dev_erase;
    fs->config.sync = _dev_sync;
    fs->config.connect = _dev_connect;
    fs->config.send = _dev_send;
    fs->config.recv = _dev_recv;
#if SATUFS_FILE_BUFFER_SIZE
    fs->config.file_buffer = fs->file_buf;
#endif
#if SATUFS_READ_BUFFER_SIZE
    fs->config.read_buffer = fs->read_buf;
#endif
#if SATUFS_PROG_BUFFER_SIZE
    fs->config.prog_buffer = fs->prog_buf;
#endif

    return mtd_init(fs->dev);
}

static int _format(vfs_mount_t *mountp)
{
    satufs_desc_t *fs = mountp->private_data;

    DEBUG("satufs: format: mountp=%p\n", (void *)mountp);
    int ret = prepare(fs);
    if (ret) {
        return -ENODEV;
    }

    ret = sfs_format(&fs->fs, &fs->config);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _mount(vfs_mount_t *mountp)
{
    satufs_desc_t *fs = mountp->private_data;

    DEBUG("satufs: mount: mountp=%p\n", (void *)mountp);
    int ret = prepare(fs);
    if (ret) {
        return -ENODEV;
    }

    ret = sfs_mount(&fs->fs, &fs->config);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _umount(vfs_mount_t *mountp)
{
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: umount: mountp=%p\n", (void *)mountp);

    int ret = sfs_unmount(&fs->fs);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _unlink(vfs_mount_t *mountp, const char *name)
{
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: unlink: mountp=%p, name=%s\n",
          (void *)mountp, name);

    int ret = sfs_remove(&fs->fs, name);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _rename(vfs_mount_t *mountp, const char *from_path, const char *to_path)
{
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: rename: mountp=%p, from=%s, to=%s\n",
          (void *)mountp, from_path, to_path);

    int ret = sfs_rename(&fs->fs, from_path, to_path);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _mkdir(vfs_mount_t *mountp, const char *name, mode_t mode)
{
    (void)mode;
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: mkdir: mountp=%p, name=%s, mode=%" PRIu32 "\n",
          (void *)mountp, name, (uint32_t)mode);

    int ret = sfs_mkdir(&fs->fs, name);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _rmdir(vfs_mount_t *mountp, const char *name)
{
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: rmdir: mountp=%p, name=%s\n",
          (void *)mountp, name);

    int ret = sfs_remove(&fs->fs, name);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _open(vfs_file_t *filp, const char *name, int flags, mode_t mode, const char *abs_path)
{
    satufs_desc_t *fs = filp->mp->private_data;
    sfs_file_t *fp = (sfs_file_t *)&filp->private_data.buffer;
    (void) abs_path;
    (void) mode;

    mutex_lock(&fs->lock);

    DEBUG("satufs: open: filp=%p, fp=%p\n", (void *)filp, (void *)fp);

    int l_flags = 0;
    if ((flags & O_ACCMODE) == O_RDONLY) {
        l_flags |= SFS_O_RDONLY;
    }
    if ((flags & O_APPEND) == O_APPEND) {
        l_flags |= SFS_O_APPEND;
    }
    if ((flags & O_TRUNC) == O_TRUNC) {
        l_flags |= SFS_O_TRUNC;
    }
    if ((flags & O_CREAT) == O_CREAT) {
        l_flags |= SFS_O_CREAT;
    }
    if ((flags & O_ACCMODE) == O_WRONLY) {
        l_flags |= SFS_O_WRONLY;
    }
    if ((flags & O_ACCMODE) == O_RDWR) {
        l_flags |= SFS_O_RDWR;
    }
    if ((flags & O_EXCL) == O_EXCL) {
        l_flags |= SFS_O_EXCL;
    }

    DEBUG("satufs: open: %s (abs_path: %s), flags: 0x%x\n", name, abs_path, (int) l_flags);

    int ret = sfs_file_open(&fs->fs, fp, name, l_flags);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _close(vfs_file_t *filp)
{
    satufs_desc_t *fs = filp->mp->private_data;
    sfs_file_t *fp = (sfs_file_t *)&filp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: close: filp=%p, fp=%p\n", (void *)filp, (void *)fp);

    int ret = sfs_file_close(&fs->fs, fp);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static ssize_t _write(vfs_file_t *filp, const void *src, size_t nbytes)
{
    satufs_desc_t *fs = filp->mp->private_data;
    sfs_file_t *fp = (sfs_file_t *)&filp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: write: filp=%p, fp=%p, src=%p, nbytes=%u\n",
          (void *)filp, (void *)fp, (void *)src, (unsigned)nbytes);

    ssize_t ret = sfs_file_write(&fs->fs, fp, src, nbytes);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static ssize_t _read(vfs_file_t *filp, void *dest, size_t nbytes)
{
    satufs_desc_t *fs = filp->mp->private_data;
    sfs_file_t *fp = (sfs_file_t *)&filp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: read: filp=%p, fp=%p, dest=%p, nbytes=%u\n",
          (void *)filp, (void *)fp, (void *)dest, (unsigned)nbytes);

    ssize_t ret = sfs_file_read(&fs->fs, fp, dest, nbytes);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static off_t _lseek(vfs_file_t *filp, off_t off, int whence)
{
    satufs_desc_t *fs = filp->mp->private_data;
    sfs_file_t *fp = (sfs_file_t *)&filp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: seek: filp=%p, fp=%p, off=%ld, whence=%d\n",
          (void *)filp, (void *)fp, (long)off, whence);

    int ret = sfs_file_seek(&fs->fs, fp, off, whence);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _stat(vfs_mount_t *mountp, const char *restrict path, struct stat *restrict buf)
{
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: stat: mountp=%p, path=%s, buf=%p\n",
          (void *)mountp, path, (void *)buf);

    struct sfs_info info;
    int ret = sfs_stat(&fs->fs, path, &info);
    mutex_unlock(&fs->lock);
    /* info.name */
    buf->st_size = info.size;
    switch (info.type) {
    case SFS_TYPE_REG:
        buf->st_mode = S_IFREG;
        break;
    case SFS_TYPE_DIR:
        buf->st_mode = S_IFDIR;
        break;
    }

    return satufs_err_to_errno(ret);
}

static int _traverse_cb(void *param, sfs_block_t block)
{
    (void)block;
    unsigned long *nb_blocks = param;
    (*nb_blocks)++;

    return 0;
}

static int _statvfs(vfs_mount_t *mountp, const char *restrict path, struct statvfs *restrict buf)
{
    (void)path;
    satufs_desc_t *fs = mountp->private_data;

    mutex_lock(&fs->lock);

    DEBUG("satufs: statvfs: mountp=%p, path=%s, buf=%p\n",
          (void *)mountp, path, (void *)buf);

    unsigned long nb_blocks = 0;
    int ret = sfs_traverse(&fs->fs, _traverse_cb, &nb_blocks);
    mutex_unlock(&fs->lock);

    buf->f_bsize = fs->fs.cfg->block_size;      /* block size */
    buf->f_frsize = fs->fs.cfg->block_size;     /* fundamental block size */
    buf->f_blocks = fs->fs.cfg->block_count;    /* Blocks total */
    buf->f_bfree = buf->f_blocks - nb_blocks;   /* Blocks free */
    buf->f_bavail = buf->f_blocks - nb_blocks;  /* Blocks available to non-privileged processes */
    buf->f_flag = ST_NOSUID;
    buf->f_namemax = SFS_NAME_MAX;

    return satufs_err_to_errno(ret);
}

static int _opendir(vfs_DIR *dirp, const char *dirname, const char *abs_path)
{
    (void)abs_path;
    satufs_desc_t *fs = dirp->mp->private_data;
    sfs_dir_t *dir = (sfs_dir_t *)&dirp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: opendir: dirp=%p, dirname=%s (abs_path=%s)\n",
          (void *)dirp, dirname, abs_path);

    int ret = sfs_dir_open(&fs->fs, dir, dirname);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _readdir(vfs_DIR *dirp, vfs_dirent_t *entry)
{
    satufs_desc_t *fs = dirp->mp->private_data;
    sfs_dir_t *dir = (sfs_dir_t *)&dirp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: readdir: dirp=%p, entry=%p\n",
          (void *)dirp, (void *)entry);

    struct sfs_info info;
    int ret = sfs_dir_read(&fs->fs, dir, &info);
    if (ret >= 0) {
        entry->d_ino = info.type;
        entry->d_name[0] = '/';
        strncpy(entry->d_name + 1, info.name, VFS_NAME_MAX - 1);
    }

    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
}

static int _closedir(vfs_DIR *dirp)
{
    satufs_desc_t *fs = dirp->mp->private_data;
    sfs_dir_t *dir = (sfs_dir_t *)&dirp->private_data.buffer;

    mutex_lock(&fs->lock);

    DEBUG("satufs: closedir: dirp=%p\n", (void *)dirp);

    int ret = sfs_dir_close(&fs->fs, dir);
    mutex_unlock(&fs->lock);

    return satufs_err_to_errno(ret);
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
    .statvfs = _statvfs,
};

static const vfs_file_ops_t satufs_file_ops = {
    .open = _open,
    .close = _close,
    .read = _read,
    .write = _write,
    .lseek = _lseek,
};

static const vfs_dir_ops_t satufs_dir_ops = {
    .opendir = _opendir,
    .readdir = _readdir,
    .closedir = _closedir,
};

const vfs_file_system_t satufs_file_system = {
    .fs_op = &satufs_fs_ops,
    .f_op = &satufs_file_ops,
    .d_op = &satufs_dir_ops,
};
