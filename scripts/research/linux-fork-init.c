// SPDX-License-Identifier: Apache-2.0
// Minimal Linux PID 1 for the VM fork experiment.
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t physical_address(void *address)
{
    int fd = open("/proc/self/pagemap", O_RDONLY);
    if (fd < 0)
        err(1, "pagemap");
    uint64_t entry;
    off_t offset = ((uintptr_t)address / 4096) * sizeof(entry);
    if (pread(fd, &entry, sizeof(entry), offset) != sizeof(entry))
        err(1, "read pagemap");
    close(fd);
    if (!(entry & (1ULL << 63)))
        errx(1, "Page is not resident");
    return (entry & ((1ULL << 55) - 1)) * 4096 + (uintptr_t)address % 4096;
}

int main(void)
{
    mkdir("/dev", 0755);
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0)
        err(1, "mount devtmpfs");
    int console = open("/dev/ttyS0", O_RDWR);
    if (console < 0)
        err(1, "serial");
    dup2(console, STDOUT_FILENO);
    dup2(console, STDERR_FILENO);
    setvbuf(stdout, NULL, _IONBF, 0);
    mkdir("/proc", 0755);
    if (mount("proc", "/proc", "proc", 0, NULL) < 0)
        err(1, "mount proc");

    int disk = open("/dev/vda", O_RDONLY | O_DIRECT);
    if (disk < 0)
        err(1, "open virtio-blk");
    _Alignas(4096) char disk_data[4096] = {0};
    if (pread(disk, disk_data, sizeof(disk_data), 0) != sizeof(disk_data) ||
        memcmp(disk_data, "fork-device-state", 17))
        errx(1, "Seed virtio-blk read failed");
    size_t size = 32 * 1024 * 1024;
    volatile uint64_t *data = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile uint64_t *command = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED || command == MAP_FAILED)
        err(1, "mmap");
    for (size_t i = 0; i < size / sizeof(*data); i++)
        data[i] = 10;
    *command = 0;
    if (mlock((void *)data, size) < 0 || mlock((void *)command, 4096) < 0)
        err(1, "mlock");
    printf("FORK_READY %lu %lu\n", physical_address((void *)command),
           physical_address((void *)data));
#ifdef FORK_SERIAL_CONTROL
    char input[32] = {0};
    size_t used = 0;
    while (used + 1 < sizeof(input)) {
        if (read(console, &input[used], 1) != 1)
            err(1, "read serial command");
        if (input[used++] == '\n')
            break;
    }
    *command = strtoul(input, NULL, 10);
    if (*command != 20 && *command != 30)
        errx(1, "Invalid serial command");
#else
    while (*command == 0)
        usleep(1000);
#endif
    uint64_t value = *command;
    uint64_t initial = data[0];
    for (size_t i = 0; i < size / sizeof(*data); i++)
        if (data[i] != 10)
            errx(1, "Unexpected inherited data at %zu: %lu", i, data[i]);
    memset(disk_data, 0, sizeof(disk_data));
    if (pread(disk, disk_data, sizeof(disk_data), 0) != sizeof(disk_data) ||
        memcmp(disk_data, "fork-device-state", 17))
        errx(1, "Restored virtio-blk read failed");
    printf("FORK_DISK_OK value=%lu\n", value);
    data[0] = value;
    printf("FORK_RESULT initial=%lu value=%lu\n", initial, data[0]);
    for (;;) {
#ifdef FORK_SERIAL_CONTROL
        printf("FORK_ALIVE value=%lu\n", data[0]);
        sleep(1);
#endif
        if (data[0] != value)
            errx(1, "Isolation failure");
        usleep(1000);
    }
}
