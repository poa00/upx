/*  powerpc-linux.elf-fold.S -- linkage to C code to process ELF binary
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) 1996-2025 Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) 1996-2025 Laszlo Molnar
*  Copyright (C) 2000-2025 John F. Reiser
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; see the file COPYING.
*  If not, write to the Free Software Foundation, Inc.,
*  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*
*  Markus F.X.J. Oberhumer              Laszlo Molnar
*  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
*
*  John F. Reiser
*  <jreiser@users.sourceforge.net>
*/

NBPW= 4  // Number of Bytes Per Word
AL_STK= 0x10  // stack alignment
#include "arch/powerpc/32/macros.S"
#include "arch/powerpc/32/ppc_regs.h"

PATH_MAX= 4096  // /usr/include/linux/limits.h

AT_NULL= 0

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4

sz_l_info= 12
sz_p_info= 12

MAP_PRIVATE=   0x02
MAP_FIXED=     0x10

PROT_READ=     0x1

O_RDONLY=       0

OVERHEAD= 2048

// http://refspecs.linuxfoundation.org/elf/elfspec_ppc.pdf  p.3-17 (pdf p.33)
// SZ_LINKA= (2 + max(0, #params - 8))*NBPW  // (sp,lr, arg9,arg10, ... )
SZ_LINKA= (2 + 2)*NBPW  // (sp,pc, arg9,arg10,... ) and 16-byte aligned
SZ_FRAME= SZ_LINKA

// In:
r_exp=   31  // f_exp == &decompress
  r_buf= 30
r_ADRU=  29  // &base to unmap
r_LENU=  28  // length to unmap
r_fd=    27  // open fd of /proc/self/exe
r_auxv=  26
r_elfa=  25  // original &Elf32_Ehdr of stub
r_ADRX=  24  // compressed input
r_LENX=  23  // total size
r_FLD=   22
// Local:
cblk=    21
  r_90b=   r_FLD
r_PMASK= 20  // (in) PAGE_MASK
av_hi=   19
av_len=  18

page_mask:
        .int -0x1000  // default page mask (4KiB)
        .int 0  // something else?
        b fold_begin

        .balign 4
get_page_mask: .globl get_page_mask
        mflr r0  // retaddr
        call 0f; 0: mflr a0
        mtlr r0  // original retaddr
        lwz a0,page_mask - 0b(a0)
        blr

Pprotect: .globl Pprotect
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b mprotect

Psync: .globl Psync
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b msync

Pmap: .globl Pmap
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b mmap

Punmap: .globl Punmap
        mflr r0; bl 0f; 0: mflr r6; mtlr r0; lwz r0,page_mask - 0b(r6)
        andc r0,a0,r0  // offset within page
        sub a0,a0,r0
        add a1,a1,r0
        b munmap

fold_begin:
        mtctr r0  // # words before argc  FIXME: fragile
        lwz r0,0(r_FLD)  // O_BINFO | is_ptinterp | unmap_all_pages
        slwi r0,r0,3*4
        mtcrf 0x8,r0  // cr4.eq = unmap_all_pages
        call L90
L90b:
        .asciz "   =/proc/self/exe"
L_PFX= 4  // strlen("   =")
        .balign 4
L90:
        mflr r_90b
// slide {<<stuff>>,argc,argv,0,env,0,auxv} down with maximum room before strings
        la a1,-NBPW(sp)  // src ready for lwzu
    beq cr4,0f; la sp,-(-AL_STK & (-1+ AL_STK + (NBPW + L_PFX + PATH_MAX)))(sp); 0:
        la a0,-NBPW(sp)  // dst ready for stwu
0: // copy stuff below argc (count in r0 at fold_begin)
        lwzu r0,NBPW(a1)
        stwu r0,NBPW(a0); bdnz 0b

        lwzu r0,NBPW(a1)  // argc (could be zero!)
        stwu r0,NBPW(a0)
0: // copy argv
        lwzu r0,NBPW(a1); cmplwi cr0,r0,0
        stwu r0,NBPW(a0); bne cr0,0b
0: // copy env
        lwzu r0,NBPW(a1); cmplwi cr0,r0,0
        stwu r0,NBPW(a0); bne cr0,0b

        la r_auxv,NBPW(a0)
0: // copy auxv
        lwz  r0,NBPW(a1); cmplwi cr0,r0,AT_NULL
        stw  r0,NBPW(a0)
        lwzu r0,2*NBPW(a1)
        stwu r0,2*NBPW(a0); bne cr0,0b

        La av_hi,NBPW(a0)  // tmp end of auxv

    beq cr4,no_pse_env
        subf av_len,r_auxv,av_hi  // length of auxv
        lwz  r0,0(r_90b)  // "    ="
        la cblk,NBPW(a1)  // original &strings
        stwu r0,NBPW(a0)
        la  r_buf,L_PFX(a0)  // buffer
// r_fd = open("/proc/self/exe", O_RDONLY)
        li a1,O_RDONLY
        la a0,L_PFX(r_90b)  //     "/proc/self/exe"
        call open; mr r_fd,a0
// readlink("/proc/self/exe", buffer, -1+ PATH_MAX)
        li a2,-1+ PATH_MAX
        movr a1,r_buf  // buffer
        la a0,L_PFX(r_90b)  //     "/proc/self/exe"
        call readlink; la a2,-L_PFX(r_buf)  // a0= len; a2= buffer
        cmpwi a0,0; bgt 0f  // success
        la a2,0(r_90b)  // "   =/proc/self/exe"
        li a0,L90  - (NBPW+ L90b)  // round_up(NBPW, strlen("/proc/self/exe"))
0:
        addi a0,a0,L_PFX
        add a1,a2,a0  // beyond end of path and prefix
        mtctr a0  // strlen(env_var)
        mr a0,cblk  // old &strings
        li r0,0; stbu r0,-1(a0)  // NUL terminator
0: // slide path up
        lbzu r0,-1(a1)
        stbu r0,-1(a0); bdnz 0b
        mr cblk,a0  // new env_ptr
        clrrwi a0,a0,4  // .balign AL_STK
        la a1,NBPW(av_hi)
        sub r0,a1,sp; neg r0,r0; clrlwi r0,r0,32-4
        sub a0,a0,r0

        mr a1,av_hi
        srwi r0,av_len,2; mtctr r0
0: // slide auxv up
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0); bdnz 0b
        mr r_auxv,a0
// Add env_ptr
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0)  // env terminator
        stwu cblk,-NBPW(a0)  // added env_ptr

        sub r0,a1,sp
        srwi r0,r0,2; mtctr r0
// slide env, argv, rest up
0:
        lwzu r0,-NBPW(a1)
        stwu r0,-NBPW(a0); bdnz 0b

        mr sp,a0

no_pse_env:
        stwu sp,-(SZ_FRAME+OVERHEAD)(sp)  // allocate this frame
        mr a0,r_ADRX  // &b_info
        mr a1,r_LENX  // total_size
        mr a2,r_elfa  // elfaddr
        mr a3,r_auxv  // &Elf32_auxv_t
        la a4,SZ_FRAME(sp)  // &Elf32_Ehdr temporary space
        call upx_main  // Out: a0= entry
// entry= upx_main(b_info *a0, total_size a1, Elf32_Ehdr *a2, ELf32_auxv_t *a3,
//      tmp_ehdr[])

        la  sp,SZ_FRAME+OVERHEAD(sp)  // deallocate this frame
        mr r_exp,a0  // save &entry

sz_Ehdr= 13*NBPW
e_type= 16
ET_EXEC= 2
sz_Phdr= 8*NBPW
p_vaddr= 2*NBPW
p_memsz= 5*NBPW
// Discard pages of compressed data (includes [ADRX,+LENX) )
        lwz a1,p_memsz+sz_Phdr+sz_Ehdr(r_elfa)  // Phdr[C_TEXT= 1].p_memsz
        //lhz r0,e_type(r_elfa); cmpwi r0,ET_EXEC; bne 1f  // only ET_EXEC
        movr a0,r_elfa; call brk  // also set the brk
1:
        lwz a1,p_memsz+sz_Phdr+sz_Ehdr(r_elfa)  // Phdr[C_TEXT= 1].p_memsz
        movr a0,r_elfa; call munmap  # discard C_TEXT compressed data

    beq cr4,no_map_pse
// first page of /proc/self/exe, to preserve it despite munmap(ADRU, LENU)
        li a5,0  // offset
        movr a4,r_fd
        cmpwi a4,0; blt no_map_pse
        li a3,MAP_PRIVATE
        li a2,PROT_READ
        neg a1,r_PMASK  // page_size
        li a0,0  // kernel chooses where
        call mmap
// close /proc/self/exe
        movr a0,r_fd
        call close
no_map_pse:

AT_NULL= 0  // <elf.h>
a_type= 0
a_val= NBPW
sz_auxv= 2*NBPW

// find the escape hatch in auxv[{AT_NULL}].a_val
        mr a0,r_auxv
0:
        lwz r0,a_type(a0); lwz a1,a_val(a0); addi a0,a0,sz_auxv
        cmplwi cr0,r0,AT_NULL; bne+ cr0,0b
        mtctr a1  // escape hatch

        mr a0,r_ADRU
        mr a1,r_LENU
        li r0,SYS_munmap
        mtlr r_exp  // entry address

        lmw a2,SZ_FRAME+(a2 - r2 + 2)*NBPW - NBPW(sp) // restore registers a2 thru r31
        la sp, SZ_FRAME+32*NBPW(sp)  // deallocate outer frame

        bctr  // goto escape hatch

  section SYSCALLS

SYS_exit=  1
SYS_fork=  2
SYS_read=  3
SYS_write= 4
SYS_open=  5
SYS_close= 6

SYS_brk=       45
SYS_readlink=  85
SYS_mmap=      90
SYS_munmap=    91
SYS_ftruncate= 93
SYS_mprotect= 125
SYS_msync=    144
SYS_memfd_create= 360

exit: .globl exit
        li r0,SYS_exit;     5: b 5f
brk: .globl brk
        li r0,SYS_brk;      5: b 5f
readlink: .globl readlink
        li r0,SYS_readlink; 5: b 5f
memfd_create: .globl memfd_create
        li r0,SYS_memfd_create; b 5f
ftruncate: .globl ftruncate
        li r0,SYS_ftruncate;5: b 5f
close: .globl close
        li r0,SYS_close;    5: b 5f
write: .globl write
        li r0,SYS_write;    5: b 5f
read: .globl read
        li r0,SYS_read;     5: b 5f
open: .globl open
        li r0,SYS_open;     5: b 5f
mprotect: .globl mprotect
        li 0,SYS_mprotect;  5: b 5f
msync: .globl msync
        li 0,SYS_msync;     5: b 5f
munmap: .globl munmap
        li r0,SYS_munmap;   5: b sysgo
mmap: .globl mmap
        li r0,SYS_mmap
sysgo:
        sc
        bns+ no_fail  // 'bns': branch if No Summary[Overflow]
        li a0,-1  // failure; IGNORE errno
no_fail:
        ret

memcpy: .globl memcpy  // (dst, src, n)
        cmpwi a2,0; beq- 9f
        mtctr a2
        subi a3,a0,1
        subi a1,a1,1
0:
        lbzu r0,1(a1)
        stbu r0,1(a3)
        bdnz 0b
9:
        blr  // return original dst

memset: .globl memset  // (dst, val, n)
        cmpwi a2,0; beq- 9f
        mtctr a2
        subi a3,a0,1
0:
        stbu a1,1(a3)
        bdnz 0b
9:
        blr  // return original dst

my_bkpt: .globl my_bkpt
        teq r0,r0  // my_bkpt
        blr
/* vim:set ts=8 sw=8 et: */
