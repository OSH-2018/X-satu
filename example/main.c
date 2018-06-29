#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

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

    // Create a test file.
    int fd = open("/send", O_CREAT|O_RDWR);
    satufs_stream_info_t data;
    memset(&data, 0, sizeof(data));
    strcpy(data.magic, "satu");
    data.port = 54321;
    strcpy(data.addr, HOST_IPV6);
    data.buffer_size = 4096;
    data.head = 0;
    data.tail = 0;
    printf("Host IP address is %s\n", HOST_IPV6);
    write(fd, &data, sizeof(data));

    // Test stream write.
    res = fcntl(fd, SATU_SETMODE, SATU_MODE_STR);
    if (res < 0)
        printf("set mode failed: %s\n", strerror(-res));
    else
        printf("set mode succeeded!!\n");
    char msg[] = "hello from your IoT device!\n";
    int nbytes = write(fd, msg, strlen(msg));
    if (nbytes < 0) {
        printf("write to stream error: %s\n", strerror(-nbytes));
    }
    close(fd);

    // Start commandline.
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
