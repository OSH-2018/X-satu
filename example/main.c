#include <stdio.h>

#include "shell.h"
#include "board.h"

#include "fs/satufs_fs.h"

static satufs_desc_t fs_desc = {
    .lock = MUTEX_INIT,
};

static vfs_mount_t flash_mount = {
    .fs = &satufs_file_system,
    .mount_point = "/",
    .private_data = &fs_desc,
};

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

int main(void)
{
    // Format storage
    fs_desc.dev = MTD_0;
    int res = vfs_format(&flash_mount);
    printf("format %s\n", res < 0 ? "error" : "ok");

    // Mount SatuFS
    res = vfs_mount(&flash_mount);
    printf("mount %s\n", res < 0 ? "error" : "ok");


    // Start commandline.
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
