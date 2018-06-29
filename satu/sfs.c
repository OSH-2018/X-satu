/*
 * A little filesystem (adapted)
 *
 * Copyright (c) 2017 ARM Limited
 * Copyright (c) 2018 ksqsf
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
#include <stddef.h>
#include "sfs.h"
#include "sfs_util.h"

static sfs_ssize_t sfs_file_raw_write(sfs_t *sfs, sfs_file_t *file,
                                      const void *buffer, sfs_size_t size);

/// Caching block device operations ///
static int sfs_cache_read(sfs_t *sfs, sfs_cache_t *rcache,
        const sfs_cache_t *pcache, sfs_block_t block,
        sfs_off_t off, void *buffer, sfs_size_t size) {
    uint8_t *data = buffer;
    SFS_ASSERT(block < sfs->cfg->block_count);

    while (size > 0) {
        if (pcache && block == pcache->block && off >= pcache->off &&
                off < pcache->off + sfs->cfg->prog_size) {
            // is already in pcache?
            sfs_size_t diff = sfs_min(size,
                    sfs->cfg->prog_size - (off-pcache->off));
            memcpy(data, &pcache->buffer[off-pcache->off], diff);

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        if (block == rcache->block && off >= rcache->off &&
                off < rcache->off + sfs->cfg->read_size) {
            // is already in rcache?
            sfs_size_t diff = sfs_min(size,
                    sfs->cfg->read_size - (off-rcache->off));
            memcpy(data, &rcache->buffer[off-rcache->off], diff);

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        if (off % sfs->cfg->read_size == 0 && size >= sfs->cfg->read_size) {
            // bypass cache?
            sfs_size_t diff = size - (size % sfs->cfg->read_size);
            int err = sfs->cfg->read(sfs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // load to cache, first condition can no longer fail
        rcache->block = block;
        rcache->off = off - (off % sfs->cfg->read_size);
        int err = sfs->cfg->read(sfs->cfg, rcache->block,
                rcache->off, rcache->buffer, sfs->cfg->read_size);
        if (err) {
            return err;
        }
    }

    return 0;
}

static int sfs_cache_cmp(sfs_t *sfs, sfs_cache_t *rcache,
        const sfs_cache_t *pcache, sfs_block_t block,
        sfs_off_t off, const void *buffer, sfs_size_t size) {
    const uint8_t *data = buffer;

    for (sfs_off_t i = 0; i < size; i++) {
        uint8_t c;
        int err = sfs_cache_read(sfs, rcache, pcache,
                block, off+i, &c, 1);
        if (err) {
            return err;
        }

        if (c != data[i]) {
            return false;
        }
    }

    return true;
}

static int sfs_cache_crc(sfs_t *sfs, sfs_cache_t *rcache,
        const sfs_cache_t *pcache, sfs_block_t block,
        sfs_off_t off, sfs_size_t size, uint32_t *crc) {
    for (sfs_off_t i = 0; i < size; i++) {
        uint8_t c;
        int err = sfs_cache_read(sfs, rcache, pcache,
                block, off+i, &c, 1);
        if (err) {
            return err;
        }

        sfs_crc(crc, &c, 1);
    }

    return 0;
}

static int sfs_cache_flush(sfs_t *sfs,
        sfs_cache_t *pcache, sfs_cache_t *rcache) {
    if (pcache->block != 0xffffffff) {
        int err = sfs->cfg->prog(sfs->cfg, pcache->block,
                pcache->off, pcache->buffer, sfs->cfg->prog_size);
        if (err) {
            return err;
        }

        if (rcache) {
            int res = sfs_cache_cmp(sfs, rcache, NULL, pcache->block,
                    pcache->off, pcache->buffer, sfs->cfg->prog_size);
            if (res < 0) {
                return res;
            }

            if (!res) {
                return SFS_ERR_CORRUPT;
            }
        }

        pcache->block = 0xffffffff;
    }

    return 0;
}

static int sfs_cache_prog(sfs_t *sfs, sfs_cache_t *pcache,
        sfs_cache_t *rcache, sfs_block_t block,
        sfs_off_t off, const void *buffer, sfs_size_t size) {
    const uint8_t *data = buffer;
    SFS_ASSERT(block < sfs->cfg->block_count);

    while (size > 0) {
        if (block == pcache->block && off >= pcache->off &&
                off < pcache->off + sfs->cfg->prog_size) {
            // is already in pcache?
            sfs_size_t diff = sfs_min(size,
                    sfs->cfg->prog_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            if (off % sfs->cfg->prog_size == 0) {
                // eagerly flush out pcache if we fill up
                int err = sfs_cache_flush(sfs, pcache, rcache);
                if (err) {
                    return err;
                }
            }

            continue;
        }

        // pcache must have been flushed, either by programming and
        // entire block or manually flushing the pcache
        SFS_ASSERT(pcache->block == 0xffffffff);

        if (off % sfs->cfg->prog_size == 0 &&
                size >= sfs->cfg->prog_size) {
            // bypass pcache?
            sfs_size_t diff = size - (size % sfs->cfg->prog_size);
            int err = sfs->cfg->prog(sfs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            if (rcache) {
                int res = sfs_cache_cmp(sfs, rcache, NULL,
                        block, off, data, diff);
                if (res < 0) {
                    return res;
                }

                if (!res) {
                    return SFS_ERR_CORRUPT;
                }
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        // prepare pcache, first condition can no longer fail
        pcache->block = block;
        pcache->off = off - (off % sfs->cfg->prog_size);
    }

    return 0;
}


/// General sfs block device operations ///
static int sfs_bd_read(sfs_t *sfs, sfs_block_t block,
        sfs_off_t off, void *buffer, sfs_size_t size) {
    // if we ever do more than writes to alternating pairs,
    // this may need to consider pcache
    return sfs_cache_read(sfs, &sfs->rcache, NULL,
            block, off, buffer, size);
}

static int sfs_bd_prog(sfs_t *sfs, sfs_block_t block,
        sfs_off_t off, const void *buffer, sfs_size_t size) {
    return sfs_cache_prog(sfs, &sfs->pcache, NULL,
            block, off, buffer, size);
}

static int sfs_bd_cmp(sfs_t *sfs, sfs_block_t block,
        sfs_off_t off, const void *buffer, sfs_size_t size) {
    return sfs_cache_cmp(sfs, &sfs->rcache, NULL, block, off, buffer, size);
}

static int sfs_bd_crc(sfs_t *sfs, sfs_block_t block,
        sfs_off_t off, sfs_size_t size, uint32_t *crc) {
    return sfs_cache_crc(sfs, &sfs->rcache, NULL, block, off, size, crc);
}

static int sfs_bd_erase(sfs_t *sfs, sfs_block_t block) {
    return sfs->cfg->erase(sfs->cfg, block);
}

static int sfs_bd_sync(sfs_t *sfs) {
    sfs->rcache.block = 0xffffffff;

    int err = sfs_cache_flush(sfs, &sfs->pcache, NULL);
    if (err) {
        return err;
    }

    return sfs->cfg->sync(sfs->cfg);
}

static int sfs_net_connect(sfs_t *sfs, const char *ipv6_addr, uint16_t port, sfs_addr_t *addr)
{
    return sfs->cfg->connect(sfs->cfg, ipv6_addr, port, addr);
}

static int sfs_net_send(sfs_t *sfs, sfs_addr_t addr, const void *data, sfs_size_t len)
{
    return sfs->cfg->send(sfs->cfg, addr, data, len);
}

static int sfs_net_recv(sfs_t *sfs, sfs_addr_t addr, void *buffer, sfs_size_t maxlen, uint32_t timeout)
{
    return sfs->cfg->recv(sfs->cfg, addr, buffer, maxlen, timeout);
}

static int sfs_net_send_all(sfs_t *sfs, sfs_addr_t addr, const char *data, sfs_size_t len)
{
    unsigned nbytes = 0;
    int res;
    while (nbytes < len) {
        res = sfs_net_send(sfs, addr, data+nbytes, len-nbytes);
        if (res < 0)
            return res;
        nbytes += res;
    }
    return nbytes;
}

static int sfs_net_send_reliably(sfs_t *sfs, sfs_addr_t addr, const char *data, sfs_size_t len)
{
    int res, nsend;
    uint16_t resp;
    nsend = sfs_net_send_all(sfs, addr, data, len);
    if (nsend < 0) {
        puts("send_all failed!!!");
        return nsend;
    }
    res = sfs_net_recv(sfs, addr, &resp, sizeof(resp), sfs->cfg->timeout);
    if (res == sizeof(resp)) {
        puts("recv ok!!!");
        return nsend;
    } else {
        puts("timedout!!!");
        return SFS_ERR_TIMEDOUT;
    }
}


/// Internal operations predeclared here ///
int sfs_traverse(sfs_t *sfs, int (*cb)(void*, sfs_block_t), void *data);
static int sfs_pred(sfs_t *sfs, const sfs_block_t dir[2], sfs_dir_t *pdir);
static int sfs_parent(sfs_t *sfs, const sfs_block_t dir[2],
        sfs_dir_t *parent, sfs_entry_t *entry);
static int sfs_moved(sfs_t *sfs, const void *e);
static int sfs_relocate(sfs_t *sfs,
        const sfs_block_t oldpair[2], const sfs_block_t newpair[2]);
int sfs_deorphan(sfs_t *sfs);


/// Block allocator ///
static int sfs_alloc_lookahead(void *p, sfs_block_t block) {
    sfs_t *sfs = p;

    sfs_block_t off = ((block - sfs->free.off)
            + sfs->cfg->block_count) % sfs->cfg->block_count;

    if (off < sfs->free.size) {
        sfs->free.buffer[off / 32] |= 1U << (off % 32);
    }

    return 0;
}

static int sfs_alloc(sfs_t *sfs, sfs_block_t *block) {
    while (true) {
        while (sfs->free.i != sfs->free.size) {
            sfs_block_t off = sfs->free.i;
            sfs->free.i += 1;
            sfs->free.ack -= 1;

            if (!(sfs->free.buffer[off / 32] & (1U << (off % 32)))) {
                // found a free block
                *block = (sfs->free.off + off) % sfs->cfg->block_count;

                // eagerly find next off so an alloc ack can
                // discredit old lookahead blocks
                while (sfs->free.i != sfs->free.size &&
                        (sfs->free.buffer[sfs->free.i / 32]
                            & (1U << (sfs->free.i % 32)))) {
                    sfs->free.i += 1;
                    sfs->free.ack -= 1;
                }

                return 0;
            }
        }

        // check if we have looked at all blocks since last ack
        if (sfs->free.ack == 0) {
            SFS_WARN("No more free space %d", sfs->free.i + sfs->free.off);
            return SFS_ERR_NOSPC;
        }

        sfs->free.off = (sfs->free.off + sfs->free.size)
                % sfs->cfg->block_count;
        sfs->free.size = sfs_min(sfs->cfg->lookahead, sfs->free.ack);
        sfs->free.i = 0;

        // find mask of free blocks from tree
        memset(sfs->free.buffer, 0, sfs->cfg->lookahead/8);
        int err = sfs_traverse(sfs, sfs_alloc_lookahead, sfs);
        if (err) {
            return err;
        }
    }
}

static void sfs_alloc_ack(sfs_t *sfs) {
    sfs->free.ack = sfs->cfg->block_count;
}


/// Endian swapping functions ///
static void sfs_dir_fromle32(struct sfs_disk_dir *d) {
    d->rev     = sfs_fromle32(d->rev);
    d->size    = sfs_fromle32(d->size);
    d->tail[0] = sfs_fromle32(d->tail[0]);
    d->tail[1] = sfs_fromle32(d->tail[1]);
}

static void sfs_dir_tole32(struct sfs_disk_dir *d) {
    d->rev     = sfs_tole32(d->rev);
    d->size    = sfs_tole32(d->size);
    d->tail[0] = sfs_tole32(d->tail[0]);
    d->tail[1] = sfs_tole32(d->tail[1]);
}

static void sfs_entry_fromle32(struct sfs_disk_entry *d) {
    d->u.dir[0] = sfs_fromle32(d->u.dir[0]);
    d->u.dir[1] = sfs_fromle32(d->u.dir[1]);
}

static void sfs_entry_tole32(struct sfs_disk_entry *d) {
    d->u.dir[0] = sfs_tole32(d->u.dir[0]);
    d->u.dir[1] = sfs_tole32(d->u.dir[1]);
}

static void sfs_superblock_fromle32(struct sfs_disk_superblock *d) {
    d->root[0]     = sfs_fromle32(d->root[0]);
    d->root[1]     = sfs_fromle32(d->root[1]);
    d->block_size  = sfs_fromle32(d->block_size);
    d->block_count = sfs_fromle32(d->block_count);
    d->version     = sfs_fromle32(d->version);
}

static void sfs_superblock_tole32(struct sfs_disk_superblock *d) {
    d->root[0]     = sfs_tole32(d->root[0]);
    d->root[1]     = sfs_tole32(d->root[1]);
    d->block_size  = sfs_tole32(d->block_size);
    d->block_count = sfs_tole32(d->block_count);
    d->version     = sfs_tole32(d->version);
}


/// Metadata pair and directory operations ///
static inline void sfs_pairswap(sfs_block_t pair[2]) {
    sfs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool sfs_pairisnull(const sfs_block_t pair[2]) {
    return pair[0] == 0xffffffff || pair[1] == 0xffffffff;
}

static inline int sfs_paircmp(
        const sfs_block_t paira[2],
        const sfs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

static inline bool sfs_pairsync(
        const sfs_block_t paira[2],
        const sfs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}

static inline sfs_size_t sfs_entry_size(const sfs_entry_t *entry) {
    return 4 + entry->d.elen + entry->d.alen + entry->d.nlen;
}

static int sfs_dir_alloc(sfs_t *sfs, sfs_dir_t *dir) {
    // allocate pair of dir blocks
    for (int i = 0; i < 2; i++) {
        int err = sfs_alloc(sfs, &dir->pair[i]);
        if (err) {
            return err;
        }
    }

    // rather than clobbering one of the blocks we just pretend
    // the revision may be valid
    int err = sfs_bd_read(sfs, dir->pair[0], 0, &dir->d.rev, 4);
    dir->d.rev = sfs_fromle32(dir->d.rev);
    if (err) {
        return err;
    }

    // set defaults
    dir->d.rev += 1;
    dir->d.size = sizeof(dir->d)+4;
    dir->d.tail[0] = 0xffffffff;
    dir->d.tail[1] = 0xffffffff;
    dir->off = sizeof(dir->d);

    // don't write out yet, let caller take care of that
    return 0;
}

static int sfs_dir_fetch(sfs_t *sfs,
        sfs_dir_t *dir, const sfs_block_t pair[2]) {
    // copy out pair, otherwise may be aliasing dir
    const sfs_block_t tpair[2] = {pair[0], pair[1]};
    bool valid = false;

    // check both blocks for the most recent revision
    for (int i = 0; i < 2; i++) {
        struct sfs_disk_dir test;
        int err = sfs_bd_read(sfs, tpair[i], 0, &test, sizeof(test));
        sfs_dir_fromle32(&test);
        if (err) {
            return err;
        }

        if (valid && sfs_scmp(test.rev, dir->d.rev) < 0) {
            continue;
        }

        if ((0x7fffffff & test.size) < sizeof(test)+4 ||
            (0x7fffffff & test.size) > sfs->cfg->block_size) {
            continue;
        }

        uint32_t crc = 0xffffffff;
        sfs_dir_tole32(&test);
        sfs_crc(&crc, &test, sizeof(test));
        sfs_dir_fromle32(&test);
        err = sfs_bd_crc(sfs, tpair[i], sizeof(test),
                (0x7fffffff & test.size) - sizeof(test), &crc);
        if (err) {
            return err;
        }

        if (crc != 0) {
            continue;
        }

        valid = true;

        // setup dir in case it's valid
        dir->pair[0] = tpair[(i+0) % 2];
        dir->pair[1] = tpair[(i+1) % 2];
        dir->off = sizeof(dir->d);
        dir->d = test;
    }

    if (!valid) {
        SFS_ERROR("Corrupted dir pair at %d %d", tpair[0], tpair[1]);
        return SFS_ERR_CORRUPT;
    }

    return 0;
}

struct sfs_region {
    sfs_off_t oldoff;
    sfs_size_t oldlen;
    const void *newdata;
    sfs_size_t newlen;
};

static int sfs_dir_commit(sfs_t *sfs, sfs_dir_t *dir,
        const struct sfs_region *regions, int count) {
    // increment revision count
    dir->d.rev += 1;

    // keep pairs in order such that pair[0] is most recent
    sfs_pairswap(dir->pair);
    for (int i = 0; i < count; i++) {
        dir->d.size += regions[i].newlen - regions[i].oldlen;
    }

    const sfs_block_t oldpair[2] = {dir->pair[0], dir->pair[1]};
    bool relocated = false;

    while (true) {
        if (true) {
            int err = sfs_bd_erase(sfs, dir->pair[0]);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            uint32_t crc = 0xffffffff;
            sfs_dir_tole32(&dir->d);
            sfs_crc(&crc, &dir->d, sizeof(dir->d));
            err = sfs_bd_prog(sfs, dir->pair[0], 0, &dir->d, sizeof(dir->d));
            sfs_dir_fromle32(&dir->d);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            int i = 0;
            sfs_off_t oldoff = sizeof(dir->d);
            sfs_off_t newoff = sizeof(dir->d);
            while (newoff < (0x7fffffff & dir->d.size)-4) {
                if (i < count && regions[i].oldoff == oldoff) {
                    sfs_crc(&crc, regions[i].newdata, regions[i].newlen);
                    err = sfs_bd_prog(sfs, dir->pair[0],
                            newoff, regions[i].newdata, regions[i].newlen);
                    if (err) {
                        if (err == SFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }

                    oldoff += regions[i].oldlen;
                    newoff += regions[i].newlen;
                    i += 1;
                } else {
                    uint8_t data;
                    err = sfs_bd_read(sfs, oldpair[1], oldoff, &data, 1);
                    if (err) {
                        return err;
                    }

                    sfs_crc(&crc, &data, 1);
                    err = sfs_bd_prog(sfs, dir->pair[0], newoff, &data, 1);
                    if (err) {
                        if (err == SFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }

                    oldoff += 1;
                    newoff += 1;
                }
            }

            crc = sfs_tole32(crc);
            err = sfs_bd_prog(sfs, dir->pair[0], newoff, &crc, 4);
            crc = sfs_fromle32(crc);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            err = sfs_bd_sync(sfs);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            // successful commit, check checksum to make sure
            uint32_t ncrc = 0xffffffff;
            err = sfs_bd_crc(sfs, dir->pair[0], 0,
                    (0x7fffffff & dir->d.size)-4, &ncrc);
            if (err) {
                return err;
            }

            if (ncrc != crc) {
                goto relocate;
            }
        }

        break;
relocate:
        //commit was corrupted
        SFS_DEBUG("Bad block at %d", dir->pair[0]);

        // drop caches and prepare to relocate block
        relocated = true;
        sfs->pcache.block = 0xffffffff;

        // can't relocate superblock, filesystem is now frozen
        if (sfs_paircmp(oldpair, (const sfs_block_t[2]){0, 1}) == 0) {
            SFS_WARN("Superblock %d has become unwritable", oldpair[0]);
            return SFS_ERR_CORRUPT;
        }

        // relocate half of pair
        int err = sfs_alloc(sfs, &dir->pair[0]);
        if (err) {
            return err;
        }
    }

    if (relocated) {
        // update references if we relocated
        SFS_DEBUG("Relocating %d %d to %d %d",
                oldpair[0], oldpair[1], dir->pair[0], dir->pair[1]);
        int err = sfs_relocate(sfs, oldpair, dir->pair);
        if (err) {
            return err;
        }
    }

    // shift over any directories that are affected
    for (sfs_dir_t *d = sfs->dirs; d; d = d->next) {
        if (sfs_paircmp(d->pair, dir->pair) == 0) {
            d->pair[0] = dir->pair[0];
            d->pair[1] = dir->pair[1];
        }
    }

    return 0;
}

static int sfs_dir_update(sfs_t *sfs, sfs_dir_t *dir,
        sfs_entry_t *entry, const void *data) {
    sfs_entry_tole32(&entry->d);
    int err = sfs_dir_commit(sfs, dir, (struct sfs_region[]){
            {entry->off, sizeof(entry->d), &entry->d, sizeof(entry->d)},
            {entry->off+sizeof(entry->d), entry->d.nlen, data, entry->d.nlen}
        }, data ? 2 : 1);
    sfs_entry_fromle32(&entry->d);
    return err;
}

static int sfs_dir_append(sfs_t *sfs, sfs_dir_t *dir,
        sfs_entry_t *entry, const void *data) {
    // check if we fit, if top bit is set we do not and move on
    while (true) {
        if (dir->d.size + sfs_entry_size(entry) <= sfs->cfg->block_size) {
            entry->off = dir->d.size - 4;

            sfs_entry_tole32(&entry->d);
            int err = sfs_dir_commit(sfs, dir, (struct sfs_region[]){
                    {entry->off, 0, &entry->d, sizeof(entry->d)},
                    {entry->off, 0, data, entry->d.nlen}
                }, 2);
            sfs_entry_fromle32(&entry->d);
            return err;
        }

        // we need to allocate a new dir block
        if (!(0x80000000 & dir->d.size)) {
            sfs_dir_t olddir = *dir;
            int err = sfs_dir_alloc(sfs, dir);
            if (err) {
                return err;
            }

            dir->d.tail[0] = olddir.d.tail[0];
            dir->d.tail[1] = olddir.d.tail[1];
            entry->off = dir->d.size - 4;
            sfs_entry_tole32(&entry->d);
            err = sfs_dir_commit(sfs, dir, (struct sfs_region[]){
                    {entry->off, 0, &entry->d, sizeof(entry->d)},
                    {entry->off, 0, data, entry->d.nlen}
                }, 2);
            sfs_entry_fromle32(&entry->d);
            if (err) {
                return err;
            }

            olddir.d.size |= 0x80000000;
            olddir.d.tail[0] = dir->pair[0];
            olddir.d.tail[1] = dir->pair[1];
            return sfs_dir_commit(sfs, &olddir, NULL, 0);
        }

        int err = sfs_dir_fetch(sfs, dir, dir->d.tail);
        if (err) {
            return err;
        }
    }
}

static int sfs_dir_remove(sfs_t *sfs, sfs_dir_t *dir, sfs_entry_t *entry) {
    // check if we should just drop the directory block
    if ((dir->d.size & 0x7fffffff) == sizeof(dir->d)+4
            + sfs_entry_size(entry)) {
        sfs_dir_t pdir;
        int res = sfs_pred(sfs, dir->pair, &pdir);
        if (res < 0) {
            return res;
        }

        if (pdir.d.size & 0x80000000) {
            pdir.d.size &= dir->d.size | 0x7fffffff;
            pdir.d.tail[0] = dir->d.tail[0];
            pdir.d.tail[1] = dir->d.tail[1];
            return sfs_dir_commit(sfs, &pdir, NULL, 0);
        }
    }

    // shift out the entry
    int err = sfs_dir_commit(sfs, dir, (struct sfs_region[]){
            {entry->off, sfs_entry_size(entry), NULL, 0},
        }, 1);
    if (err) {
        return err;
    }

    // shift over any files/directories that are affected
    for (sfs_file_t *f = sfs->files; f; f = f->next) {
        if (sfs_paircmp(f->pair, dir->pair) == 0) {
            if (f->poff == entry->off) {
                f->pair[0] = 0xffffffff;
                f->pair[1] = 0xffffffff;
            } else if (f->poff > entry->off) {
                f->poff -= sfs_entry_size(entry);
            }
        }
    }

    for (sfs_dir_t *d = sfs->dirs; d; d = d->next) {
        if (sfs_paircmp(d->pair, dir->pair) == 0) {
            if (d->off > entry->off) {
                d->off -= sfs_entry_size(entry);
                d->pos -= sfs_entry_size(entry);
            }
        }
    }

    return 0;
}

static int sfs_dir_next(sfs_t *sfs, sfs_dir_t *dir, sfs_entry_t *entry) {
    while (dir->off + sizeof(entry->d) > (0x7fffffff & dir->d.size)-4) {
        if (!(0x80000000 & dir->d.size)) {
            entry->off = dir->off;
            return SFS_ERR_NOENT;
        }

        int err = sfs_dir_fetch(sfs, dir, dir->d.tail);
        if (err) {
            return err;
        }

        dir->off = sizeof(dir->d);
        dir->pos += sizeof(dir->d) + 4;
    }

    int err = sfs_bd_read(sfs, dir->pair[0], dir->off,
            &entry->d, sizeof(entry->d));
    sfs_entry_fromle32(&entry->d);
    if (err) {
        return err;
    }

    entry->off = dir->off;
    dir->off += sfs_entry_size(entry);
    dir->pos += sfs_entry_size(entry);
    return 0;
}

static int sfs_dir_find(sfs_t *sfs, sfs_dir_t *dir,
        sfs_entry_t *entry, const char **path) {
    const char *pathname = *path;
    size_t pathlen;
    entry->d.type = SFS_TYPE_DIR;
    entry->d.elen = sizeof(entry->d) - 4;
    entry->d.alen = 0;
    entry->d.nlen = 0;
    entry->d.u.dir[0] = sfs->root[0];
    entry->d.u.dir[1] = sfs->root[1];

    while (true) {
nextname:
        // skip slashes
        pathname += strspn(pathname, "/");
        pathlen = strcspn(pathname, "/");

        // skip '.' and root '..'
        if ((pathlen == 1 && memcmp(pathname, ".", 1) == 0) ||
            (pathlen == 2 && memcmp(pathname, "..", 2) == 0)) {
            pathname += pathlen;
            goto nextname;
        }

        // skip if matched by '..' in name
        const char *suffix = pathname + pathlen;
        size_t sufflen;
        int depth = 1;
        while (true) {
            suffix += strspn(suffix, "/");
            sufflen = strcspn(suffix, "/");
            if (sufflen == 0) {
                break;
            }

            if (sufflen == 2 && memcmp(suffix, "..", 2) == 0) {
                depth -= 1;
                if (depth == 0) {
                    pathname = suffix + sufflen;
                    goto nextname;
                }
            } else {
                depth += 1;
            }

            suffix += sufflen;
        }

        // found path
        if (pathname[0] == '\0') {
            return 0;
        }

        // update what we've found
        *path = pathname;

        // continue on if we hit a directory
        if (entry->d.type != SFS_TYPE_DIR) {
            return SFS_ERR_NOTDIR;
        }

        int err = sfs_dir_fetch(sfs, dir, entry->d.u.dir);
        if (err) {
            return err;
        }

        // find entry matching name
        while (true) {
            int err = sfs_dir_next(sfs, dir, entry);
            if (err) {
                return err;
            }

            if (((0x7f & entry->d.type) != SFS_TYPE_REG &&
                 (0x7f & entry->d.type) != SFS_TYPE_DIR) ||
                entry->d.nlen != pathlen) {
                continue;
            }

            int res = sfs_bd_cmp(sfs, dir->pair[0],
                    entry->off + 4+entry->d.elen+entry->d.alen,
                    pathname, pathlen);
            if (res < 0) {
                return res;
            }

            // found match
            if (res) {
                break;
            }
        }

        // check that entry has not been moved
        if (entry->d.type & 0x80) {
            int moved = sfs_moved(sfs, &entry->d.u);
            if (moved < 0 || moved) {
                return (moved < 0) ? moved : SFS_ERR_NOENT;
            }

            entry->d.type &= ~0x80;
        }

        // to next name
        pathname += pathlen;
    }
}


/// Top level directory operations ///
int sfs_mkdir(sfs_t *sfs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!sfs->deorphaned) {
        int err = sfs_deorphan(sfs);
        if (err) {
            return err;
        }
    }

    // fetch parent directory
    sfs_dir_t cwd;
    sfs_entry_t entry;
    int err = sfs_dir_find(sfs, &cwd, &entry, &path);
    if (err != SFS_ERR_NOENT || strchr(path, '/') != NULL) {
        return err ? err : SFS_ERR_EXIST;
    }

    // build up new directory
    sfs_alloc_ack(sfs);

    sfs_dir_t dir;
    err = sfs_dir_alloc(sfs, &dir);
    if (err) {
        return err;
    }
    dir.d.tail[0] = cwd.d.tail[0];
    dir.d.tail[1] = cwd.d.tail[1];

    err = sfs_dir_commit(sfs, &dir, NULL, 0);
    if (err) {
        return err;
    }

    entry.d.type = SFS_TYPE_DIR;
    entry.d.elen = sizeof(entry.d) - 4;
    entry.d.alen = 0;
    entry.d.nlen = strlen(path);
    entry.d.u.dir[0] = dir.pair[0];
    entry.d.u.dir[1] = dir.pair[1];

    cwd.d.tail[0] = dir.pair[0];
    cwd.d.tail[1] = dir.pair[1];

    err = sfs_dir_append(sfs, &cwd, &entry, path);
    if (err) {
        return err;
    }

    sfs_alloc_ack(sfs);
    return 0;
}

int sfs_dir_open(sfs_t *sfs, sfs_dir_t *dir, const char *path) {
    dir->pair[0] = sfs->root[0];
    dir->pair[1] = sfs->root[1];

    sfs_entry_t entry;
    int err = sfs_dir_find(sfs, dir, &entry, &path);
    if (err) {
        return err;
    } else if (entry.d.type != SFS_TYPE_DIR) {
        return SFS_ERR_NOTDIR;
    }

    err = sfs_dir_fetch(sfs, dir, entry.d.u.dir);
    if (err) {
        return err;
    }

    // setup head dir
    // special offset for '.' and '..'
    dir->head[0] = dir->pair[0];
    dir->head[1] = dir->pair[1];
    dir->pos = sizeof(dir->d) - 2;
    dir->off = sizeof(dir->d);

    // add to list of directories
    dir->next = sfs->dirs;
    sfs->dirs = dir;

    return 0;
}

int sfs_dir_close(sfs_t *sfs, sfs_dir_t *dir) {
    // remove from list of directories
    for (sfs_dir_t **p = &sfs->dirs; *p; p = &(*p)->next) {
        if (*p == dir) {
            *p = dir->next;
            break;
        }
    }

    return 0;
}

int sfs_dir_read(sfs_t *sfs, sfs_dir_t *dir, struct sfs_info *info) {
    memset(info, 0, sizeof(*info));

    // special offset for '.' and '..'
    if (dir->pos == sizeof(dir->d) - 2) {
        info->type = SFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        return 1;
    } else if (dir->pos == sizeof(dir->d) - 1) {
        info->type = SFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        return 1;
    }

    sfs_entry_t entry;
    while (true) {
        int err = sfs_dir_next(sfs, dir, &entry);
        if (err) {
            return (err == SFS_ERR_NOENT) ? 0 : err;
        }

        if ((0x7f & entry.d.type) != SFS_TYPE_REG &&
            (0x7f & entry.d.type) != SFS_TYPE_DIR) {
            continue;
        }

        // check that entry has not been moved
        if (entry.d.type & 0x80) {
            int moved = sfs_moved(sfs, &entry.d.u);
            if (moved < 0) {
                return moved;
            }

            if (moved) {
                continue;
            }

            entry.d.type &= ~0x80;
        }

        break;
    }

    info->type = entry.d.type;
    if (info->type == SFS_TYPE_REG) {
        info->size = entry.d.u.file.size;
    }

    int err = sfs_bd_read(sfs, dir->pair[0],
            entry.off + 4+entry.d.elen+entry.d.alen,
            info->name, entry.d.nlen);
    if (err) {
        return err;
    }

    return 1;
}

int sfs_dir_seek(sfs_t *sfs, sfs_dir_t *dir, sfs_off_t off) {
    // simply walk from head dir
    int err = sfs_dir_rewind(sfs, dir);
    if (err) {
        return err;
    }
    dir->pos = off;

    while (off > (0x7fffffff & dir->d.size)) {
        off -= 0x7fffffff & dir->d.size;
        if (!(0x80000000 & dir->d.size)) {
            return SFS_ERR_INVAL;
        }

        err = sfs_dir_fetch(sfs, dir, dir->d.tail);
        if (err) {
            return err;
        }
    }

    dir->off = off;
    return 0;
}

sfs_soff_t sfs_dir_tell(sfs_t *sfs, sfs_dir_t *dir) {
    (void)sfs;
    return dir->pos;
}

int sfs_dir_rewind(sfs_t *sfs, sfs_dir_t *dir) {
    // reload the head dir
    int err = sfs_dir_fetch(sfs, dir, dir->head);
    if (err) {
        return err;
    }

    dir->pair[0] = dir->head[0];
    dir->pair[1] = dir->head[1];
    dir->pos = sizeof(dir->d) - 2;
    dir->off = sizeof(dir->d);
    return 0;
}


/// File index list operations ///
static int sfs_ctz_index(sfs_t *sfs, sfs_off_t *off) {
    sfs_off_t size = *off;
    sfs_off_t b = sfs->cfg->block_size - 2*4;
    sfs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(sfs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*sfs_popc(i);
    return i;
}

static int sfs_ctz_find(sfs_t *sfs,
        sfs_cache_t *rcache, const sfs_cache_t *pcache,
        sfs_block_t head, sfs_size_t size,
        sfs_size_t pos, sfs_block_t *block, sfs_off_t *off) {
    if (size == 0) {
        *block = 0xffffffff;
        *off = 0;
        return 0;
    }

    sfs_off_t current = sfs_ctz_index(sfs, &(sfs_off_t){size-1});
    sfs_off_t target = sfs_ctz_index(sfs, &pos);

    while (current > target) {
        sfs_size_t skip = sfs_min(
                sfs_npw2(current-target+1) - 1,
                sfs_ctz(current));

        int err = sfs_cache_read(sfs, rcache, pcache, head, 4*skip, &head, 4);
        head = sfs_fromle32(head);
        if (err) {
            return err;
        }

        SFS_ASSERT(head >= 2 && head <= sfs->cfg->block_count);
        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

static int sfs_ctz_extend(sfs_t *sfs,
        sfs_cache_t *rcache, sfs_cache_t *pcache,
        sfs_block_t head, sfs_size_t size,
        sfs_block_t *block, sfs_off_t *off) {
    while (true) {
        // go ahead and grab a block
        sfs_block_t nblock;
        int err = sfs_alloc(sfs, &nblock);
        if (err) {
            return err;
        }
        SFS_ASSERT(nblock >= 2 && nblock <= sfs->cfg->block_count);

        if (true) {
            err = sfs_bd_erase(sfs, nblock);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            size -= 1;
            sfs_off_t index = sfs_ctz_index(sfs, &size);
            size += 1;

            // just copy out the last block if it is incomplete
            if (size != sfs->cfg->block_size) {
                for (sfs_off_t i = 0; i < size; i++) {
                    uint8_t data;
                    err = sfs_cache_read(sfs, rcache, NULL,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = sfs_cache_prog(sfs, pcache, rcache,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == SFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = size;
                return 0;
            }

            // append block
            index += 1;
            sfs_size_t skips = sfs_ctz(index) + 1;

            for (sfs_off_t i = 0; i < skips; i++) {
                head = sfs_tole32(head);
                err = sfs_cache_prog(sfs, pcache, rcache,
                        nblock, 4*i, &head, 4);
                head = sfs_fromle32(head);
                if (err) {
                    if (err == SFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = sfs_cache_read(sfs, rcache, NULL,
                            head, 4*i, &head, 4);
                    head = sfs_fromle32(head);
                    if (err) {
                        return err;
                    }
                }

                SFS_ASSERT(head >= 2 && head <= sfs->cfg->block_count);
            }

            *block = nblock;
            *off = 4*skips;
            return 0;
        }

relocate:
        SFS_DEBUG("Bad block at %d", nblock);

        // just clear cache and try a new block
        pcache->block = 0xffffffff;
    }
}

static int sfs_ctz_traverse(sfs_t *sfs,
        sfs_cache_t *rcache, const sfs_cache_t *pcache,
        sfs_block_t head, sfs_size_t size,
        int (*cb)(void*, sfs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    sfs_off_t index = sfs_ctz_index(sfs, &(sfs_off_t){size-1});

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        sfs_block_t heads[2];
        int count = 2 - (index & 1);
        err = sfs_cache_read(sfs, rcache, pcache, head, 0, &heads, count*4);
        heads[0] = sfs_fromle32(heads[0]);
        heads[1] = sfs_fromle32(heads[1]);
        if (err) {
            return err;
        }

        for (int i = 0; i < count-1; i++) {
            err = cb(data, heads[i]);
            if (err) {
                return err;
            }
        }

        head = heads[count-1];
        index -= count;
    }
}


/// Top level file operations ///
int sfs_file_open(sfs_t *sfs, sfs_file_t *file,
        const char *path, int flags) {
    // deorphan if we haven't yet, needed at most once after poweron
    if ((flags & 3) != SFS_O_RDONLY && !sfs->deorphaned) {
        int err = sfs_deorphan(sfs);
        if (err) {
            return err;
        }
    }

    // allocate entry for file if it doesn't exist
    sfs_dir_t cwd;
    sfs_entry_t entry;
    int err = sfs_dir_find(sfs, &cwd, &entry, &path);
    if (err && (err != SFS_ERR_NOENT || strchr(path, '/') != NULL)) {
        return err;
    }

    if (err == SFS_ERR_NOENT) {
        if (!(flags & SFS_O_CREAT)) {
            return SFS_ERR_NOENT;
        }

        // create entry to remember name
        entry.d.type = SFS_TYPE_REG;
        entry.d.elen = sizeof(entry.d) - 4;
        entry.d.alen = 0;
        entry.d.nlen = strlen(path);
        entry.d.u.file.head = 0xffffffff;
        entry.d.u.file.size = 0;
        err = sfs_dir_append(sfs, &cwd, &entry, path);
        if (err) {
            return err;
        }
    } else if (entry.d.type == SFS_TYPE_DIR) {
        return SFS_ERR_ISDIR;
    } else if (flags & SFS_O_EXCL) {
        return SFS_ERR_EXIST;
    }

    // setup file struct
    file->pair[0] = cwd.pair[0];
    file->pair[1] = cwd.pair[1];
    file->poff = entry.off;
    file->head = entry.d.u.file.head;
    file->size = entry.d.u.file.size;
    file->flags = flags;
    file->pos = 0;

    if (flags & SFS_O_TRUNC) {
        if (file->size != 0) {
            file->flags |= SFS_F_DIRTY;
        }
        file->head = 0xffffffff;
        file->size = 0;
    }

    // allocate buffer if needed
    file->cache.block = 0xffffffff;
    if (sfs->cfg->file_buffer) {
        if (sfs->files) {
            // already in use
            return SFS_ERR_NOMEM;
        }
        file->cache.buffer = sfs->cfg->file_buffer;
    } else if ((file->flags & 3) == SFS_O_RDONLY) {
        file->cache.buffer = sfs_malloc(sfs->cfg->read_size);
        if (!file->cache.buffer) {
            return SFS_ERR_NOMEM;
        }
    } else {
        file->cache.buffer = sfs_malloc(sfs->cfg->prog_size);
        if (!file->cache.buffer) {
            return SFS_ERR_NOMEM;
        }
    }

    // add to list of files
    file->next = sfs->files;
    sfs->files = file;

    return 0;
}

int sfs_file_close(sfs_t *sfs, sfs_file_t *file) {
    int err = sfs_file_sync(sfs, file);

    // remove from list of files
    for (sfs_file_t **p = &sfs->files; *p; p = &(*p)->next) {
        if (*p == file) {
            *p = file->next;
            break;
        }
    }

    // clean up memory
    if (!sfs->cfg->file_buffer) {
        sfs_free(file->cache.buffer);
    }

    return err;
}

int sfs_file_set_mode(sfs_t *sfs, sfs_file_t *file, int wmode)
{
    int err;
    sfs_stream_info_t data;
    
    err = sfs_file_sync(sfs, file);
    if (err < 0)
        return err;

    // connect to the server
    err = sfs_file_seek(sfs, file, 0, SFS_SEEK_SET);
    if (err < 0)
        return err;
    err = sfs_file_read(sfs, file, &data, sizeof(data));
    if (err < 0)
        return err;
    err = sfs_net_connect(sfs, data.addr, data.port, &file->addr);// FIXME: network byte-order
    if (err < 0)
        return err;

    // preallocate buffer
    if (strcmp(data.magic, "satu")) {
        file->bhead = data.head;
        file->btail = data.tail;
    }
    err = sfs_file_truncate(sfs, file, sizeof(data) + data.buffer_size);
    if (err < 0)
        return err;

    // switch wmode
    file->wmode = wmode;
    return 0;
}

static int sfs_file_relocate(sfs_t *sfs, sfs_file_t *file) {
relocate:
    SFS_DEBUG("Bad block at %d", file->block);

    // just relocate what exists into new block
    sfs_block_t nblock;
    int err = sfs_alloc(sfs, &nblock);
    if (err) {
        return err;
    }

    err = sfs_bd_erase(sfs, nblock);
    if (err) {
        if (err == SFS_ERR_CORRUPT) {
            goto relocate;
        }
        return err;
    }

    // either read from dirty cache or disk
    for (sfs_off_t i = 0; i < file->off; i++) {
        uint8_t data;
        err = sfs_cache_read(sfs, &sfs->rcache, &file->cache,
                file->block, i, &data, 1);
        if (err) {
            return err;
        }

        err = sfs_cache_prog(sfs, &sfs->pcache, &sfs->rcache,
                nblock, i, &data, 1);
        if (err) {
            if (err == SFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }
    }

    // copy over new state of file
    memcpy(file->cache.buffer, sfs->pcache.buffer, sfs->cfg->prog_size);
    file->cache.block = sfs->pcache.block;
    file->cache.off = sfs->pcache.off;
    sfs->pcache.block = 0xffffffff;

    file->block = nblock;
    return 0;
}

static int sfs_file_flush(sfs_t *sfs, sfs_file_t *file) {
    if (file->flags & SFS_F_READING) {
        // just drop read cache
        file->cache.block = 0xffffffff;
        file->flags &= ~SFS_F_READING;
    }

    if (file->flags & SFS_F_WRITING) {
        sfs_off_t pos = file->pos;

        // copy over anything after current branch
        sfs_file_t orig = {
            .head = file->head,
            .size = file->size,
            .flags = SFS_O_RDONLY,
            .pos = file->pos,
            .cache = sfs->rcache,
        };
        sfs->rcache.block = 0xffffffff;

        while (file->pos < file->size) {
            // copy over a byte at a time, leave it up to caching
            // to make this efficient
            uint8_t data;
            sfs_ssize_t res = sfs_file_read(sfs, &orig, &data, 1);
            if (res < 0) {
                return res;
            }

            res = sfs_file_raw_write(sfs, file, &data, 1);
            if (res < 0) {
                return res;
            }

            // keep our reference to the rcache in sync
            if (sfs->rcache.block != 0xffffffff) {
                orig.cache.block = 0xffffffff;
                sfs->rcache.block = 0xffffffff;
            }
        }

        // write out what we have
        while (true) {
            int err = sfs_cache_flush(sfs, &file->cache, &sfs->rcache);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            break;
relocate:
            err = sfs_file_relocate(sfs, file);
            if (err) {
                return err;
            }
        }

        // actual file updates
        file->head = file->block;
        file->size = file->pos;
        file->flags &= ~SFS_F_WRITING;
        file->flags |= SFS_F_DIRTY;

        file->pos = pos;
    }

    return 0;
}

int sfs_file_sync(sfs_t *sfs, sfs_file_t *file) {
    int err = sfs_file_flush(sfs, file);
    if (err) {
        return err;
    }

    if ((file->flags & SFS_F_DIRTY) &&
            !(file->flags & SFS_F_ERRED) &&
            !sfs_pairisnull(file->pair)) {
        // update dir entry
        sfs_dir_t cwd;
        err = sfs_dir_fetch(sfs, &cwd, file->pair);
        if (err) {
            return err;
        }

        sfs_entry_t entry = {.off = file->poff};
        err = sfs_bd_read(sfs, cwd.pair[0], entry.off,
                &entry.d, sizeof(entry.d));
        sfs_entry_fromle32(&entry.d);
        if (err) {
            return err;
        }

        SFS_ASSERT(entry.d.type == SFS_TYPE_REG);
        entry.d.u.file.head = file->head;
        entry.d.u.file.size = file->size;

        err = sfs_dir_update(sfs, &cwd, &entry, NULL);
        if (err) {
            return err;
        }

        file->flags &= ~SFS_F_DIRTY;
    }

    return 0;
}

sfs_ssize_t sfs_file_read(sfs_t *sfs, sfs_file_t *file,
        void *buffer, sfs_size_t size) {
    uint8_t *data = buffer;
    sfs_size_t nsize = size;

    if ((file->flags & 3) == SFS_O_WRONLY) {
        return SFS_ERR_BADF;
    }

    if (file->flags & SFS_F_WRITING) {
        // flush out any writes
        int err = sfs_file_flush(sfs, file);
        if (err) {
            return err;
        }
    }

    if (file->pos >= file->size) {
        // eof if past end
        return 0;
    }

    size = sfs_min(size, file->size - file->pos);
    nsize = size;

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & SFS_F_READING) ||
                file->off == sfs->cfg->block_size) {
            int err = sfs_ctz_find(sfs, &file->cache, NULL,
                    file->head, file->size,
                    file->pos, &file->block, &file->off);
            if (err) {
                return err;
            }

            file->flags |= SFS_F_READING;
        }

        // read as much as we can in current block
        sfs_size_t diff = sfs_min(nsize, sfs->cfg->block_size - file->off);
        int err = sfs_cache_read(sfs, &file->cache, NULL,
                file->block, file->off, data, diff);
        if (err) {
            return err;
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;
    }

    return size;
}

static sfs_ssize_t sfs_file_raw_write(sfs_t *sfs, sfs_file_t *file,
        const void *buffer, sfs_size_t size) {
    const uint8_t *data = buffer;
    sfs_size_t nsize = size;

    if ((file->flags & 3) == SFS_O_RDONLY) {
        return SFS_ERR_BADF;
    }

    if (file->flags & SFS_F_READING) {
        // drop any reads
        int err = sfs_file_flush(sfs, file);
        if (err) {
            return err;
        }
    }

    if ((file->flags & SFS_O_APPEND) && file->pos < file->size) {
        file->pos = file->size;
    }

    if (!(file->flags & SFS_F_WRITING) && file->pos > file->size) {
        // fill with zeros
        sfs_off_t pos = file->pos;
        file->pos = file->size;

        while (file->pos < pos) {
            sfs_ssize_t res = sfs_file_raw_write(sfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return res;
            }
        }
    }

    while (nsize > 0) {
        // check if we need a new block
        if (!(file->flags & SFS_F_WRITING) ||
                file->off == sfs->cfg->block_size) {
            if (!(file->flags & SFS_F_WRITING) && file->pos > 0) {
                // find out which block we're extending from
                int err = sfs_ctz_find(sfs, &file->cache, NULL,
                        file->head, file->size,
                        file->pos-1, &file->block, &file->off);
                if (err) {
                    file->flags |= SFS_F_ERRED;
                    return err;
                }

                // mark cache as dirty since we may have read data into it
                file->cache.block = 0xffffffff;
            }

            // extend file with new blocks
            sfs_alloc_ack(sfs);
            int err = sfs_ctz_extend(sfs, &sfs->rcache, &file->cache,
                    file->block, file->pos,
                    &file->block, &file->off);
            if (err) {
                file->flags |= SFS_F_ERRED;
                return err;
            }

            file->flags |= SFS_F_WRITING;
        }

        // program as much as we can in current block
        sfs_size_t diff = sfs_min(nsize, sfs->cfg->block_size - file->off);
        while (true) {
            int err = sfs_cache_prog(sfs, &file->cache, &sfs->rcache,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == SFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= SFS_F_ERRED;
                return err;
            }

            break;
relocate:
            err = sfs_file_relocate(sfs, file);
            if (err) {
                file->flags |= SFS_F_ERRED;
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        sfs_alloc_ack(sfs);
    }

    file->flags &= ~SFS_F_ERRED;
    return size;
}

static int sfs_stream_try_clear_buffer(sfs_t *sfs, sfs_file_t *file)
{
    int res, total=0;
    if (file->btail == file->bhead) {
        return 0;
    } else if (file->btail < file->bhead) {
        // FIXME: WTF?  Maybe overflow...
        file->head = 0;
        goto commit;
    } else {
        char buf[256], c;
        while (file->btail - file->bhead > 256) {
            res = sfs_file_read(sfs, file, buf, sizeof(buf));
            if (res < 0)
                return res;
            res = sfs_net_send_reliably(sfs, file->addr, buf, res);
            if (res < 0)
                return res;
            total += res;
            file->bhead += res;
        }

        while (file->btail < file->bhead) {
            res = sfs_file_read(sfs, file, &c, 1);
            if (res < 0)
                return res;
            res = sfs_net_send_reliably(sfs, file->addr, &c, 1);
            if (res < 0)
                return res;
            total += 1;
            file->bhead += 1;
        }
        goto commit;
    }

commit:
    sfs_file_seek(sfs, file, offsetof(sfs_stream_info_t, head), SFS_SEEK_CUR);
    sfs_file_raw_write(sfs, file, &file->bhead, sizeof(file->bhead));
    return total;
}

static int sfs_stream_stash(sfs_t *sfs, sfs_file_t *file,
                            const char *buffer, sfs_size_t size)
{
    int nwritten=0, res;

    sfs_file_seek(sfs, file, file->btail, SFS_SEEK_SET);
    while (file->btail - file->bhead > sfs->cfg->prog_size) {
        res = sfs_file_raw_write(sfs, file, buffer+nwritten, size-nwritten);
        if (res < 0)
            goto commit;
        file->btail += res;
    }
    res=0;
commit:
    sfs_file_seek(sfs, file, offsetof(sfs_stream_info_t, tail), SFS_SEEK_SET);
    sfs_file_raw_write(sfs, file, &file->btail, sizeof(file->btail));
    return res;
}

sfs_ssize_t sfs_file_stream_write(sfs_t *sfs, sfs_file_t *file,
                                  const char *buffer, sfs_size_t size)
{
    int nsend;

    // try to send buffered data
    while ((nsend = sfs_stream_try_clear_buffer(sfs, file)) > 0);
    if (nsend < 0) {
        return nsend;
    }

    // send all
    if ((nsend = sfs_net_send_reliably(sfs, file->addr, buffer, size)) < 0) {
        puts("send_reliably failed!!!");
        if (nsend != SFS_ERR_TIMEDOUT) {
            return nsend;
        }
    }
    if (nsend == SFS_ERR_TIMEDOUT) {
        nsend = 0;
    }
    if (nsend < (long) size) {
        sfs_stream_stash(sfs, file, buffer+nsend, size-nsend);
    }
    return size;
}

sfs_ssize_t sfs_file_write(sfs_t *sfs, sfs_file_t *file,
        const void *buffer, sfs_size_t size) {
    if (file->wmode == SFS_WMODE_STR)
        return sfs_file_stream_write(sfs, file, buffer, size);
    else
        return sfs_file_raw_write(sfs, file, buffer, size);
}

sfs_soff_t sfs_file_seek(sfs_t *sfs, sfs_file_t *file,
        sfs_soff_t off, int whence) {
    // write out everything beforehand, may be noop if rdonly
    int err = sfs_file_flush(sfs, file);
    if (err) {
        return err;
    }

    // update pos
    if (whence == SFS_SEEK_SET) {
        file->pos = off;
    } else if (whence == SFS_SEEK_CUR) {
        if (off < 0 && (sfs_off_t)-off > file->pos) {
            return SFS_ERR_INVAL;
        }

        file->pos = file->pos + off;
    } else if (whence == SFS_SEEK_END) {
        if (off < 0 && (sfs_off_t)-off > file->size) {
            return SFS_ERR_INVAL;
        }

        file->pos = file->size + off;
    }

    return file->pos;
}

int sfs_file_truncate(sfs_t *sfs, sfs_file_t *file, sfs_off_t size) {
    if ((file->flags & 3) == SFS_O_RDONLY) {
        return SFS_ERR_BADF;
    }

    sfs_off_t oldsize = sfs_file_size(sfs, file);
    if (size < oldsize) {
        // need to flush since directly changing metadata
        int err = sfs_file_flush(sfs, file);
        if (err) {
            return err;
        }

        // lookup new head in ctz skip list
        err = sfs_ctz_find(sfs, &file->cache, NULL,
                file->head, file->size,
                size, &file->head, &(sfs_off_t){0});
        if (err) {
            return err;
        }

        file->size = size;
        file->flags |= SFS_F_DIRTY;
    } else if (size > oldsize) {
        sfs_off_t pos = file->pos;

        // flush+seek if not already at end
        if (file->pos != oldsize) {
            int err = sfs_file_seek(sfs, file, 0, SFS_SEEK_END);
            if (err < 0) {
                return err;
            }
        }

        // fill with zeros
        while (file->pos < size) {
            sfs_ssize_t res = sfs_file_raw_write(sfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return res;
            }
        }

        // restore pos
        int err = sfs_file_seek(sfs, file, pos, SFS_SEEK_SET);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

sfs_soff_t sfs_file_tell(sfs_t *sfs, sfs_file_t *file) {
    (void)sfs;
    return file->pos;
}

int sfs_file_rewind(sfs_t *sfs, sfs_file_t *file) {
    sfs_soff_t res = sfs_file_seek(sfs, file, 0, SFS_SEEK_SET);
    if (res < 0) {
        return res;
    }

    return 0;
}

sfs_soff_t sfs_file_size(sfs_t *sfs, sfs_file_t *file) {
    (void)sfs;
    if (file->flags & SFS_F_WRITING) {
        return sfs_max(file->pos, file->size);
    } else {
        return file->size;
    }
}


/// General fs operations ///
int sfs_stat(sfs_t *sfs, const char *path, struct sfs_info *info) {
    sfs_dir_t cwd;
    sfs_entry_t entry;
    int err = sfs_dir_find(sfs, &cwd, &entry, &path);
    if (err) {
        return err;
    }

    memset(info, 0, sizeof(*info));
    info->type = entry.d.type;
    if (info->type == SFS_TYPE_REG) {
        info->size = entry.d.u.file.size;
    }

    if (sfs_paircmp(entry.d.u.dir, sfs->root) == 0) {
        strcpy(info->name, "/");
    } else {
        err = sfs_bd_read(sfs, cwd.pair[0],
                entry.off + 4+entry.d.elen+entry.d.alen,
                info->name, entry.d.nlen);
        if (err) {
            return err;
        }
    }

    return 0;
}

int sfs_remove(sfs_t *sfs, const char *path) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!sfs->deorphaned) {
        int err = sfs_deorphan(sfs);
        if (err) {
            return err;
        }
    }

    sfs_dir_t cwd;
    sfs_entry_t entry;
    int err = sfs_dir_find(sfs, &cwd, &entry, &path);
    if (err) {
        return err;
    }

    sfs_dir_t dir;
    if (entry.d.type == SFS_TYPE_DIR) {
        // must be empty before removal, checking size
        // without masking top bit checks for any case where
        // dir is not empty
        err = sfs_dir_fetch(sfs, &dir, entry.d.u.dir);
        if (err) {
            return err;
        } else if (dir.d.size != sizeof(dir.d)+4) {
            return SFS_ERR_NOTEMPTY;
        }
    }

    // remove the entry
    err = sfs_dir_remove(sfs, &cwd, &entry);
    if (err) {
        return err;
    }

    // if we were a directory, find pred, replace tail
    if (entry.d.type == SFS_TYPE_DIR) {
        int res = sfs_pred(sfs, dir.pair, &cwd);
        if (res < 0) {
            return res;
        }

        SFS_ASSERT(res); // must have pred
        cwd.d.tail[0] = dir.d.tail[0];
        cwd.d.tail[1] = dir.d.tail[1];

        err = sfs_dir_commit(sfs, &cwd, NULL, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

int sfs_rename(sfs_t *sfs, const char *oldpath, const char *newpath) {
    // deorphan if we haven't yet, needed at most once after poweron
    if (!sfs->deorphaned) {
        int err = sfs_deorphan(sfs);
        if (err) {
            return err;
        }
    }

    // find old entry
    sfs_dir_t oldcwd;
    sfs_entry_t oldentry;
    int err = sfs_dir_find(sfs, &oldcwd, &oldentry, &oldpath);
    if (err) {
        return err;
    }

    // allocate new entry
    sfs_dir_t newcwd;
    sfs_entry_t preventry;
    err = sfs_dir_find(sfs, &newcwd, &preventry, &newpath);
    if (err && (err != SFS_ERR_NOENT || strchr(newpath, '/') != NULL)) {
        return err;
    }

    bool prevexists = (err != SFS_ERR_NOENT);
    bool samepair = (sfs_paircmp(oldcwd.pair, newcwd.pair) == 0);

    // must have same type
    if (prevexists && preventry.d.type != oldentry.d.type) {
        return SFS_ERR_ISDIR;
    }

    sfs_dir_t dir;
    if (prevexists && preventry.d.type == SFS_TYPE_DIR) {
        // must be empty before removal, checking size
        // without masking top bit checks for any case where
        // dir is not empty
        err = sfs_dir_fetch(sfs, &dir, preventry.d.u.dir);
        if (err) {
            return err;
        } else if (dir.d.size != sizeof(dir.d)+4) {
            return SFS_ERR_NOTEMPTY;
        }
    }

    // mark as moving
    oldentry.d.type |= 0x80;
    err = sfs_dir_update(sfs, &oldcwd, &oldentry, NULL);
    if (err) {
        return err;
    }

    // update pair if newcwd == oldcwd
    if (samepair) {
        newcwd = oldcwd;
    }

    // move to new location
    sfs_entry_t newentry = preventry;
    newentry.d = oldentry.d;
    newentry.d.type &= ~0x80;
    newentry.d.nlen = strlen(newpath);

    if (prevexists) {
        err = sfs_dir_update(sfs, &newcwd, &newentry, newpath);
        if (err) {
            return err;
        }
    } else {
        err = sfs_dir_append(sfs, &newcwd, &newentry, newpath);
        if (err) {
            return err;
        }
    }

    // update pair if newcwd == oldcwd
    if (samepair) {
        oldcwd = newcwd;
    }

    // remove old entry
    err = sfs_dir_remove(sfs, &oldcwd, &oldentry);
    if (err) {
        return err;
    }

    // if we were a directory, find pred, replace tail
    if (prevexists && preventry.d.type == SFS_TYPE_DIR) {
        int res = sfs_pred(sfs, dir.pair, &newcwd);
        if (res < 0) {
            return res;
        }

        SFS_ASSERT(res); // must have pred
        newcwd.d.tail[0] = dir.d.tail[0];
        newcwd.d.tail[1] = dir.d.tail[1];

        err = sfs_dir_commit(sfs, &newcwd, NULL, 0);
        if (err) {
            return err;
        }
    }

    return 0;
}


/// Filesystem operations ///
static int sfs_init(sfs_t *sfs, const struct sfs_config *cfg) {
    sfs->cfg = cfg;

    // setup read cache
    sfs->rcache.block = 0xffffffff;
    if (sfs->cfg->read_buffer) {
        sfs->rcache.buffer = sfs->cfg->read_buffer;
    } else {
        sfs->rcache.buffer = sfs_malloc(sfs->cfg->read_size);
        if (!sfs->rcache.buffer) {
            return SFS_ERR_NOMEM;
        }
    }

    // setup program cache
    sfs->pcache.block = 0xffffffff;
    if (sfs->cfg->prog_buffer) {
        sfs->pcache.buffer = sfs->cfg->prog_buffer;
    } else {
        sfs->pcache.buffer = sfs_malloc(sfs->cfg->prog_size);
        if (!sfs->pcache.buffer) {
            return SFS_ERR_NOMEM;
        }
    }

    // setup lookahead, round down to nearest 32-bits
    SFS_ASSERT(sfs->cfg->lookahead % 32 == 0);
    SFS_ASSERT(sfs->cfg->lookahead > 0);
    if (sfs->cfg->lookahead_buffer) {
        sfs->free.buffer = sfs->cfg->lookahead_buffer;
    } else {
        sfs->free.buffer = sfs_malloc(sfs->cfg->lookahead/8);
        if (!sfs->free.buffer) {
            return SFS_ERR_NOMEM;
        }
    }

    // check that program and read sizes are multiples of the block size
    SFS_ASSERT(sfs->cfg->prog_size % sfs->cfg->read_size == 0);
    SFS_ASSERT(sfs->cfg->block_size % sfs->cfg->prog_size == 0);

    // check that the block size is large enough to fit ctz pointers
    SFS_ASSERT(4*sfs_npw2(0xffffffff / (sfs->cfg->block_size-2*4))
            <= sfs->cfg->block_size);

    // setup default state
    sfs->root[0] = 0xffffffff;
    sfs->root[1] = 0xffffffff;
    sfs->files = NULL;
    sfs->dirs = NULL;
    sfs->deorphaned = false;

    return 0;
}

static int sfs_deinit(sfs_t *sfs) {
    // free allocated memory
    if (!sfs->cfg->read_buffer) {
        sfs_free(sfs->rcache.buffer);
    }

    if (!sfs->cfg->prog_buffer) {
        sfs_free(sfs->pcache.buffer);
    }

    if (!sfs->cfg->lookahead_buffer) {
        sfs_free(sfs->free.buffer);
    }

    return 0;
}

int sfs_format(sfs_t *sfs, const struct sfs_config *cfg) {
    int err = sfs_init(sfs, cfg);
    if (err) {
        return err;
    }

    // create free lookahead
    memset(sfs->free.buffer, 0, sfs->cfg->lookahead/8);
    sfs->free.off = 0;
    sfs->free.size = sfs_min(sfs->cfg->lookahead, sfs->cfg->block_count);
    sfs->free.i = 0;
    sfs_alloc_ack(sfs);

    // create superblock dir
    sfs_dir_t superdir;
    err = sfs_dir_alloc(sfs, &superdir);
    if (err) {
        return err;
    }

    // write root directory
    sfs_dir_t root;
    err = sfs_dir_alloc(sfs, &root);
    if (err) {
        return err;
    }

    err = sfs_dir_commit(sfs, &root, NULL, 0);
    if (err) {
        return err;
    }

    sfs->root[0] = root.pair[0];
    sfs->root[1] = root.pair[1];

    // write superblocks
    sfs_superblock_t superblock = {
        .off = sizeof(superdir.d),
        .d.type = SFS_TYPE_SUPERBLOCK,
        .d.elen = sizeof(superblock.d) - sizeof(superblock.d.magic) - 4,
        .d.nlen = sizeof(superblock.d.magic),
        .d.version = SFS_DISK_VERSION,
        .d.magic = {"satufs99"},
        .d.block_size  = sfs->cfg->block_size,
        .d.block_count = sfs->cfg->block_count,
        .d.root = {sfs->root[0], sfs->root[1]},
    };
    superdir.d.tail[0] = root.pair[0];
    superdir.d.tail[1] = root.pair[1];
    superdir.d.size = sizeof(superdir.d) + sizeof(superblock.d) + 4;

    // write both pairs to be safe
    sfs_superblock_tole32(&superblock.d);
    bool valid = false;
    for (int i = 0; i < 2; i++) {
        err = sfs_dir_commit(sfs, &superdir, (struct sfs_region[]){
                {sizeof(superdir.d), sizeof(superblock.d),
                 &superblock.d, sizeof(superblock.d)}
            }, 1);
        if (err && err != SFS_ERR_CORRUPT) {
            return err;
        }

        valid = valid || !err;
    }

    if (!valid) {
        return SFS_ERR_CORRUPT;
    }

    // sanity check that fetch works
    err = sfs_dir_fetch(sfs, &superdir, (const sfs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    sfs_alloc_ack(sfs);
    return sfs_deinit(sfs);
}

int sfs_mount(sfs_t *sfs, const struct sfs_config *cfg) {
    int err = sfs_init(sfs, cfg);
    if (err) {
        return err;
    }

    // setup free lookahead
    sfs->free.off = 0;
    sfs->free.size = 0;
    sfs->free.i = 0;
    sfs_alloc_ack(sfs);

    // load superblock
    sfs_dir_t dir;
    sfs_superblock_t superblock;
    err = sfs_dir_fetch(sfs, &dir, (const sfs_block_t[2]){0, 1});
    if (err && err != SFS_ERR_CORRUPT) {
        return err;
    }

    if (!err) {
        err = sfs_bd_read(sfs, dir.pair[0], sizeof(dir.d),
                &superblock.d, sizeof(superblock.d));
        sfs_superblock_fromle32(&superblock.d);
        if (err) {
            return err;
        }

        sfs->root[0] = superblock.d.root[0];
        sfs->root[1] = superblock.d.root[1];
    }

    if (err || memcmp(superblock.d.magic, "satufs99", 8) != 0) {
        SFS_ERROR("Invalid superblock at %d %d", 0, 1);
        return SFS_ERR_CORRUPT;
    }

    uint16_t major_version = (0xffff & (superblock.d.version >> 16));
    uint16_t minor_version = (0xffff & (superblock.d.version >>  0));
    if ((major_version != SFS_DISK_VERSION_MAJOR ||
         minor_version > SFS_DISK_VERSION_MINOR)) {
        SFS_ERROR("Invalid version %d.%d", major_version, minor_version);
        return SFS_ERR_INVAL;
    }

    return 0;
}

int sfs_unmount(sfs_t *sfs) {
    return sfs_deinit(sfs);
}


/// Satufs specific operations ///
int sfs_traverse(sfs_t *sfs, int (*cb)(void*, sfs_block_t), void *data) {
    if (sfs_pairisnull(sfs->root)) {
        return 0;
    }

    // iterate over metadata pairs
    sfs_dir_t dir;
    sfs_entry_t entry;
    sfs_block_t cwd[2] = {0, 1};

    while (true) {
        for (int i = 0; i < 2; i++) {
            int err = cb(data, cwd[i]);
            if (err) {
                return err;
            }
        }

        int err = sfs_dir_fetch(sfs, &dir, cwd);
        if (err) {
            return err;
        }

        // iterate over contents
        while (dir.off + sizeof(entry.d) <= (0x7fffffff & dir.d.size)-4) {
            err = sfs_bd_read(sfs, dir.pair[0], dir.off,
                    &entry.d, sizeof(entry.d));
            sfs_entry_fromle32(&entry.d);
            if (err) {
                return err;
            }

            dir.off += sfs_entry_size(&entry);
            if ((0x70 & entry.d.type) == (0x70 & SFS_TYPE_REG)) {
                err = sfs_ctz_traverse(sfs, &sfs->rcache, NULL,
                        entry.d.u.file.head, entry.d.u.file.size, cb, data);
                if (err) {
                    return err;
                }
            }
        }

        cwd[0] = dir.d.tail[0];
        cwd[1] = dir.d.tail[1];

        if (sfs_pairisnull(cwd)) {
            break;
        }
    }

    // iterate over any open files
    for (sfs_file_t *f = sfs->files; f; f = f->next) {
        if (f->flags & SFS_F_DIRTY) {
            int err = sfs_ctz_traverse(sfs, &sfs->rcache, &f->cache,
                    f->head, f->size, cb, data);
            if (err) {
                return err;
            }
        }

        if (f->flags & SFS_F_WRITING) {
            int err = sfs_ctz_traverse(sfs, &sfs->rcache, &f->cache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }

    return 0;
}

static int sfs_pred(sfs_t *sfs, const sfs_block_t dir[2], sfs_dir_t *pdir) {
    if (sfs_pairisnull(sfs->root)) {
        return 0;
    }

    // iterate over all directory directory entries
    int err = sfs_dir_fetch(sfs, pdir, (const sfs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    while (!sfs_pairisnull(pdir->d.tail)) {
        if (sfs_paircmp(pdir->d.tail, dir) == 0) {
            return true;
        }

        err = sfs_dir_fetch(sfs, pdir, pdir->d.tail);
        if (err) {
            return err;
        }
    }

    return false;
}

static int sfs_parent(sfs_t *sfs, const sfs_block_t dir[2],
        sfs_dir_t *parent, sfs_entry_t *entry) {
    if (sfs_pairisnull(sfs->root)) {
        return 0;
    }

    parent->d.tail[0] = 0;
    parent->d.tail[1] = 1;

    // iterate over all directory directory entries
    while (!sfs_pairisnull(parent->d.tail)) {
        int err = sfs_dir_fetch(sfs, parent, parent->d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = sfs_dir_next(sfs, parent, entry);
            if (err && err != SFS_ERR_NOENT) {
                return err;
            }

            if (err == SFS_ERR_NOENT) {
                break;
            }

            if (((0x70 & entry->d.type) == (0x70 & SFS_TYPE_DIR)) &&
                 sfs_paircmp(entry->d.u.dir, dir) == 0) {
                return true;
            }
        }
    }

    return false;
}

static int sfs_moved(sfs_t *sfs, const void *e) {
    if (sfs_pairisnull(sfs->root)) {
        return 0;
    }

    // skip superblock
    sfs_dir_t cwd;
    int err = sfs_dir_fetch(sfs, &cwd, (const sfs_block_t[2]){0, 1});
    if (err) {
        return err;
    }

    // iterate over all directory directory entries
    sfs_entry_t entry;
    while (!sfs_pairisnull(cwd.d.tail)) {
        err = sfs_dir_fetch(sfs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        while (true) {
            err = sfs_dir_next(sfs, &cwd, &entry);
            if (err && err != SFS_ERR_NOENT) {
                return err;
            }

            if (err == SFS_ERR_NOENT) {
                break;
            }

            if (!(0x80 & entry.d.type) &&
                 memcmp(&entry.d.u, e, sizeof(entry.d.u)) == 0) {
                return true;
            }
        }
    }

    return false;
}

static int sfs_relocate(sfs_t *sfs,
        const sfs_block_t oldpair[2], const sfs_block_t newpair[2]) {
    // find parent
    sfs_dir_t parent;
    sfs_entry_t entry;
    int res = sfs_parent(sfs, oldpair, &parent, &entry);
    if (res < 0) {
        return res;
    }

    if (res) {
        // update disk, this creates a desync
        entry.d.u.dir[0] = newpair[0];
        entry.d.u.dir[1] = newpair[1];

        int err = sfs_dir_update(sfs, &parent, &entry, NULL);
        if (err) {
            return err;
        }

        // update internal root
        if (sfs_paircmp(oldpair, sfs->root) == 0) {
            SFS_DEBUG("Relocating root %d %d", newpair[0], newpair[1]);
            sfs->root[0] = newpair[0];
            sfs->root[1] = newpair[1];
        }

        // clean up bad block, which should now be a desync
        return sfs_deorphan(sfs);
    }

    // find pred
    res = sfs_pred(sfs, oldpair, &parent);
    if (res < 0) {
        return res;
    }

    if (res) {
        // just replace bad pair, no desync can occur
        parent.d.tail[0] = newpair[0];
        parent.d.tail[1] = newpair[1];

        return sfs_dir_commit(sfs, &parent, NULL, 0);
    }

    // couldn't find dir, must be new
    return 0;
}

int sfs_deorphan(sfs_t *sfs) {
    sfs->deorphaned = true;

    if (sfs_pairisnull(sfs->root)) {
        return 0;
    }

    sfs_dir_t pdir = {.d.size = 0x80000000};
    sfs_dir_t cwd = {.d.tail[0] = 0, .d.tail[1] = 1};

    // iterate over all directory directory entries
    while (!sfs_pairisnull(cwd.d.tail)) {
        int err = sfs_dir_fetch(sfs, &cwd, cwd.d.tail);
        if (err) {
            return err;
        }

        // check head blocks for orphans
        if (!(0x80000000 & pdir.d.size)) {
            // check if we have a parent
            sfs_dir_t parent;
            sfs_entry_t entry;
            int res = sfs_parent(sfs, pdir.d.tail, &parent, &entry);
            if (res < 0) {
                return res;
            }

            if (!res) {
                // we are an orphan
                SFS_DEBUG("Found orphan %d %d",
                        pdir.d.tail[0], pdir.d.tail[1]);

                pdir.d.tail[0] = cwd.d.tail[0];
                pdir.d.tail[1] = cwd.d.tail[1];

                err = sfs_dir_commit(sfs, &pdir, NULL, 0);
                if (err) {
                    return err;
                }

                break;
            }

            if (!sfs_pairsync(entry.d.u.dir, pdir.d.tail)) {
                // we have desynced
                SFS_DEBUG("Found desync %d %d",
                        entry.d.u.dir[0], entry.d.u.dir[1]);

                pdir.d.tail[0] = entry.d.u.dir[0];
                pdir.d.tail[1] = entry.d.u.dir[1];

                err = sfs_dir_commit(sfs, &pdir, NULL, 0);
                if (err) {
                    return err;
                }

                break;
            }
        }

        // check entries for moves
        sfs_entry_t entry;
        while (true) {
            err = sfs_dir_next(sfs, &cwd, &entry);
            if (err && err != SFS_ERR_NOENT) {
                return err;
            }

            if (err == SFS_ERR_NOENT) {
                break;
            }

            // found moved entry
            if (entry.d.type & 0x80) {
                int moved = sfs_moved(sfs, &entry.d.u);
                if (moved < 0) {
                    return moved;
                }

                if (moved) {
                    SFS_DEBUG("Found move %d %d",
                            entry.d.u.dir[0], entry.d.u.dir[1]);
                    err = sfs_dir_remove(sfs, &cwd, &entry);
                    if (err) {
                        return err;
                    }
                } else {
                    SFS_DEBUG("Found partial move %d %d",
                            entry.d.u.dir[0], entry.d.u.dir[1]);
                    entry.d.type &= ~0x80;
                    err = sfs_dir_update(sfs, &cwd, &entry, NULL);
                    if (err) {
                        return err;
                    }
                }
            }
        }

        memcpy(&pdir, &cwd, sizeof(pdir));
    }

    return 0;
}

