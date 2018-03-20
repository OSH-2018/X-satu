#!/usr/bin/env python3

import os
import sys
import errno
import argparse

# FIXME: 'fusepy' is supposed to be 'fuse'; determine if the host is Debian!
from fusepy import FUSE, FuseOSError, Operations


class Satu(Operations):
    def __init__(self):
        pass

    # File system methods
    # ===================
    def access(self, path, mode):
        pass

    def chmod(self, path, mode):
        pass

    def chown(self, path, mode):
        pass

    def getattr(self, path, fh=None):
        pass

    def readdir(self, path, fh):
        pass

    def readlink(self, path):
        pass

    def mknod(self, path, mode, dev):
        pass

    def rmdir(self, path, mode):
        pass

    def statfs(self, path):
        pass

    def unlink(self, path):
        pass

    def symlink(self, path):
        pass

    def rename(self, old, new):
        pass

    def link(self, target, name):
        pass

    def utimens(self, path, times=None):
        pass

    # File methods
    # ============
    def open(self, path, flags):
        pass

    def create(self, path, mode, fi=None):
        pass

    def read(self, path, length, offset, fh):
        pass

    def write(self, path, buf, offset, fh):
        pass

    def truncate(self, path, length, fh=None):
        pass

    def flush(self, path, fh):
        pass

    def release(self, path, fh):
        pass

    def fsync(self, path, fdatasync, fh):
        pass


def main(mountpoint):
    # FIXME: confirm these options are relevant
    FUSE(Satu(), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Mount a SatuFS")
    parser.add_argument('mountpoint', metavar='mountpoint')
    args = parser.parse_args()
    main(args.mountpoint)
