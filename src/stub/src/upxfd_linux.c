/* upxfd_create.c -- simplify upx_mmap_and_fd_linux for non-Android

   This file is part of the UPX executable compressor.

   Copyright (C) 2023 John F. Reiser
   All Rights Reserved.
 */

extern void my_bkpt(void const *, ...);

#if defined(__i386__) //}{
#define ANDROID_FRIEND 1
#define addr_string(string) ({ \
    char const *str; \
    asm("call 0f; .asciz \"" string "\"; 0: pop %0" \
/*out*/ : "=r"(str) ); \
    str; \
})
#elif defined(__arm__) //}{
#define ANDROID_FRIEND 1
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .string \"" string "\"; .balign 4; 0: mov %0,lr" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "lr"); \
    str; \
})
#elif defined(__mips__) //}{
#define ANDROID_FRIEND 0
#define addr_string(string) ({ \
    char const *str; \
    asm(".set noreorder; bal 0f; nop; .asciz \"" string "\"; .balign 4\n0: move %0,$31; .set reorder" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "ra"); \
    str; \
})
#elif defined(__powerpc__)  /*}{*/
#define ANDROID_FRIEND 0
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .asciz \"" string "\"; .balign 4; 0: mflr %0" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "lr"); \
    str; \
})
#elif defined(__powerpc64__) //}{
#define ANDROID_FRIEND 0
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .string \"" string "\"; .balign 4; 0: mflr %0" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "lr"); \
    str; \
})
#elif defined(__x86_64) //}{
#define ANDROID_FRIEND 0
#define addr_string(string) ({ \
    char const *str; \
    asm("lea 9f(%%rip),%0; .section STRCON; 9:.asciz \"" string "\"; .previous" \
/*out*/ : "=r"(str) ); \
    str; \
})
#elif defined(__aarch64__) //}{
#define ANDROID_FRIEND 0
#define addr_string(string) ({ \
    char const *str; \
    asm("bl 0f; .string \"" string "\"; .balign 4; 0: mov %0,x30" \
/*out*/ : "=r"(str) \
/* in*/ : \
/*und*/ : "x30"); \
    str; \
})
#else  //}{
#define ANDROID_FRIEND 0
#error  addr_string
#endif  //}

#ifdef __mips__  //{
#define NO_WANT_CLOSE 1
#define NO_WANT_EXIT 1
#define NO_WANT_MMAP 1
#define NO_WANT_MPROTECT 1
#define NO_WANT_MSYNC 1
#define NO_WANT_OPEN 1
#define NO_WANT_READ 1
#define NO_WANT_WRITE 1
extern int open(char const *pathname, int flags, unsigned mode);
#endif  //}
#include "include/linux.h"  // syscall decls; i386 inlines via "int 0x80"

#define MFD_EXEC 0x10
//#define O_RDWR 2
#define O_DIRECTORY 0200000  /* 0x010000 asm-generic/fcntl.h */
#define O_TMPFILE 020000000  /* 0x400000 asm-generic/fcntl.h */
#define EINVAL 22 /* asm-generic/errno-base.h */

extern int memfd_create(char const *, unsigned);
extern int ftruncate(int, size_t);
extern unsigned long get_page_mask(void);

// Implementation for Linux-native, where memfd_create
// (or /dev/shm) works.  Saves space in contrast to
// upxfd_android (or Android emulator), which must
// fall back to  /data/data/$APP_NAME/cache/upxAAA ,
// and also must work around inconsistent __NR_ftruncate.
// 1. Try memfd_create
// 2. Try /dev/shm
unsigned long upx_mmap_and_fd_linux( // returns (mapped_addr | (1+ fd))
    void *ptr  // desired address
    , unsigned datlen  // mapped length
    , char *pathname  // 0 ==> get_upxfn_path()
)
{
    (void)pathname;  // FIXME NYI
    char const *const name = addr_string("upx");
    int fd = memfd_create(name, MFD_EXEC);
    if (-EINVAL == fd) { // 2024-10-15 MFD_EXEC unknown to ubuntu-20.04
        fd = memfd_create(name, 0);  // try again
    }
    if (fd < 0) { // last chance for Linux
        fd = open(addr_string("/dev/shm"), O_RDWR | O_DIRECTORY | O_TMPFILE, 0700);
        if (fd < 0) {
            return (unsigned long)(long)fd;
        }
        // Beware: /dev/shm might limit write() to 8KiB at a time.
    }
    int rv = ftruncate(fd, datlen);
    if (rv < 0) {
        return (unsigned long)(long)rv;
    }
    ptr = mmap(ptr, datlen, PROT_READ|PROT_WRITE,
        (ptr ? MAP_FIXED : 0)|MAP_SHARED, fd, 0);
    unsigned long const page_mask = get_page_mask();
    if (page_mask <= (unsigned long)ptr) {
        return (unsigned long)ptr;  // errno
    }
    return (unsigned long)ptr + (1+ (unsigned)fd);
}
