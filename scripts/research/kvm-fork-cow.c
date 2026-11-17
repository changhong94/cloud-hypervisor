// SPDX-License-Identifier: Apache-2.0
// Build: cc -std=c11 -O2 -Wall -Wextra -Werror kvm-fork-cow.c -o /tmp/kvm-fork-cow
// Run on x86_64 with access to /dev/kvm: timeout 30s /tmp/kvm-fork-cow
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    RAM_SIZE = 64 * 1024 * 1024,
    CODE = 0x1000,
    DATA = 0x2000,
    PORT = 0x10,
};

struct vm {
    int fd;
    int cpu;
    struct kvm_run *run;
};

static struct vm create_vm(int kvm, unsigned char *ram)
{
    struct vm vm;
    vm.fd = ioctl(kvm, KVM_CREATE_VM, 0);
    if (vm.fd < 0)
        err(1, "KVM_CREATE_VM");

    struct kvm_userspace_memory_region region = {
        .memory_size = RAM_SIZE,
        .userspace_addr = (uintptr_t)ram,
    };
    if (ioctl(vm.fd, KVM_SET_USER_MEMORY_REGION, &region) < 0)
        err(1, "KVM_SET_USER_MEMORY_REGION");

    vm.cpu = ioctl(vm.fd, KVM_CREATE_VCPU, 0);
    if (vm.cpu < 0)
        err(1, "KVM_CREATE_VCPU");

    int size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (size < 0)
        err(1, "KVM_GET_VCPU_MMAP_SIZE");
    vm.run = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, vm.cpu, 0);
    if (vm.run == MAP_FAILED)
        err(1, "mmap kvm_run");

    struct kvm_sregs sregs;
    if (ioctl(vm.cpu, KVM_GET_SREGS, &sregs) < 0)
        err(1, "KVM_GET_SREGS");
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    if (ioctl(vm.cpu, KVM_SET_SREGS, &sregs) < 0)
        err(1, "KVM_SET_SREGS");
    return vm;
}

static void expect_guest_byte(struct vm vm, int write_value, int expected)
{
    struct kvm_regs regs = {
        .rip = write_value < 0 ? CODE + 3 : CODE,
        .rax = write_value < 0 ? 0 : (uint64_t)write_value,
        .rflags = 2,
    };
    if (ioctl(vm.cpu, KVM_SET_REGS, &regs) < 0)
        err(1, "KVM_SET_REGS");
    if (ioctl(vm.cpu, KVM_RUN, 0) < 0)
        err(1, "KVM_RUN");
    if (vm.run->exit_reason != KVM_EXIT_IO ||
        vm.run->io.direction != KVM_EXIT_IO_OUT ||
        vm.run->io.port != PORT || vm.run->io.size != 1 ||
        vm.run->io.count != 1)
        errx(1, "Unexpected KVM exit: %u", vm.run->exit_reason);

    unsigned char value = *((unsigned char *)vm.run + vm.run->io.data_offset);
    printf("pid=%ld guest write=%d read=%u expected=%d\n",
           (long)getpid(), write_value, value, expected);
    if (value != expected)
        errx(1, "Guest RAM isolation check failed");

    // Complete the OUT before the next KVM_SET_REGS or the host fork.
    if (ioctl(vm.cpu, KVM_RUN, 0) < 0)
        err(1, "KVM_RUN after OUT");
    if (vm.run->exit_reason != KVM_EXIT_HLT)
        errx(1, "Expected KVM_EXIT_HLT, got %u", vm.run->exit_reason);
}

struct memory_usage {
    long rss;
    long pss;
    long private_dirty;
    long shared_dirty;
};

static struct memory_usage ram_usage(pid_t pid, const unsigned char *ram)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/smaps", (long)pid);
    FILE *smaps = fopen(path, "r");
    if (!smaps)
        err(1, "%s", path);

    struct memory_usage usage = {0};
    char line[512];
    unsigned long start, end;
    int found = 0;
    while (fgets(line, sizeof(line), smaps)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (found)
                break;
            found = start == (uintptr_t)ram && end - start == RAM_SIZE;
        } else if (found) {
            if (sscanf(line, "Rss: %ld", &usage.rss) == 1 ||
                sscanf(line, "Pss: %ld", &usage.pss) == 1 ||
                sscanf(line, "Private_Dirty: %ld", &usage.private_dirty) == 1 ||
                sscanf(line, "Shared_Dirty: %ld", &usage.shared_dirty) == 1)
                continue;
        }
    }
    fclose(smaps);
    if (!found || usage.rss != RAM_SIZE / 1024)
        errx(1, "Expected fully resident guest RAM in %s, got %ld KiB",
             path, usage.rss);
    printf("pid=%ld RAM KiB: RSS=%ld PSS=%ld private_dirty=%ld shared_dirty=%ld\n",
           (long)pid, usage.rss, usage.pss, usage.private_dirty,
           usage.shared_dirty);
    return usage;
}

static void signal_peer(int fd)
{
    if (write(fd, "x", 1) != 1)
        err(1, "write synchronization pipe");
}

static void wait_for_peer(int fd)
{
    char token;
    if (read(fd, &token, 1) != 1)
        errx(1, "Peer exited before reaching the synchronization point");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm < 0)
        err(1, "/dev/kvm");
    if (ioctl(kvm, KVM_GET_API_VERSION, 0) != KVM_API_VERSION)
        errx(1, "Unexpected KVM API version");

    int backing = memfd_create("kvm-fork-cow-ram", MFD_CLOEXEC);
    if (backing < 0 || ftruncate(backing, RAM_SIZE) < 0)
        err(1, "Allocate RAM backing");
    unsigned char *ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE, backing, 0);
    if (ram == MAP_FAILED)
        err(1, "mmap guest RAM");
    if (madvise(ram, RAM_SIZE, MADV_NOHUGEPAGE) < 0)
        err(1, "MADV_NOHUGEPAGE");
    memset(ram, 0x5a, RAM_SIZE);

    // 16-bit real mode: mov [0x2000], al; mov al, [0x2000]; out 0x10, al; hlt
    const unsigned char code[] = {0xa2, 0x00, 0x20, 0xa0, 0x00, 0x20,
                                  0xe6, PORT, 0xf4};
    memcpy(ram + CODE, code, sizeof(code));
    struct vm parent = create_vm(kvm, ram);
    expect_guest_byte(parent, 10, 10);
    puts("Before fork");
    ram_usage(getpid(), ram);

    int to_child[2], to_parent[2];
    if (pipe(to_child) < 0 || pipe(to_parent) < 0)
        err(1, "pipe");

    pid_t child = fork();
    if (child < 0)
        err(1, "fork");
    if (child == 0) {
        close(to_child[1]);
        close(to_parent[0]);
        close(parent.cpu);
        close(parent.fd);
        struct vm child_vm = create_vm(kvm, ram);
        signal_peer(to_parent[1]);
        wait_for_peer(to_child[0]);
        expect_guest_byte(child_vm, -1, 10);
        expect_guest_byte(child_vm, 30, 30);
        signal_peer(to_parent[1]);
        wait_for_peer(to_child[0]);
        _exit(0);
    }

    close(to_child[0]);
    close(to_parent[1]);
    wait_for_peer(to_parent[0]);
    puts("After fork and child KVM registration, before guest writes");
    struct memory_usage parent_before = ram_usage(getpid(), ram);
    struct memory_usage child_before = ram_usage(child, ram);
    if (parent_before.pss + child_before.pss != RAM_SIZE / 1024 ||
        parent_before.private_dirty != 0 || child_before.private_dirty != 0)
        errx(1, "Guest RAM was not fully shared after fork");

    expect_guest_byte(parent, 20, 20);
    signal_peer(to_child[1]);
    wait_for_peer(to_parent[0]);
    expect_guest_byte(parent, -1, 20);

    puts("After both guests wrote the same GPA");
    struct memory_usage parent_after = ram_usage(getpid(), ram);
    struct memory_usage child_after = ram_usage(child, ram);
    long page_kib = sysconf(_SC_PAGESIZE) / 1024;
    if (parent_after.pss + child_after.pss != RAM_SIZE / 1024 + page_kib ||
        parent_after.private_dirty != page_kib ||
        child_after.private_dirty != page_kib)
        errx(1, "Expected exactly one extra physical page after guest writes");

    signal_peer(to_child[1]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        errx(1, "Child did not exit cleanly");
    puts("PASS: guest RAM shared at fork; guest writes split exactly one page");
    return 0;
}
