# Satu FS

The Satu file system is an Internet-aware file system for IoT systems,
which has an emphasis on developer-frienliness and portability.

Currently, the only supported platform is RIOT OS.

**WARNING**: the Satu FS is under development and not ready for anyone
and any use.

## Features

(Temporarily) None.

## Structure

This repository contains the source code of the Satu FS, and a package
for use with RIOT OS.

```
.
├── Documentation    Documentation of the Satu FS
├── port             A port package for RIOT OS
├── RIOT             The RIOT OS
└── satu             The Satu FS
```

We hope more OSs can be supported in the future, so we don't simply
mix `/port` with `/satu`.

## Authors

See [the contibutors page](https://github.com/OSH-2018/X-satu/graphs/contributors).

## License

GPLv3. See `COPYING`. Note that this is a temporary decision and we
may change it in the future.
