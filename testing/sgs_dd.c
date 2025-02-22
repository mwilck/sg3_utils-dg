/*
 * Test code for the extensions to the Linux OS SCSI generic ("sg")
 * device driver.
 * Copyright (C) 1999-2021 D. Gilbert and P. Allworth
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is a specialization of the Unix "dd" command in which
 * one or both of the given files is a scsi generic device. A block size
 * ('bs') is assumed to be 512 if not given. This program complains if
 * 'ibs' or 'obs' are given with some other value than 'bs'.
 * If 'if' is not given or 'if=-' then stdin is assumed. If 'of' is
 * not given of 'of=-' then stdout assumed. The multipliers "c, b, k, m"
 * are recognized on numeric arguments.
 *
 * A non-standard argument "bpt" (blocks per transfer) is added to control
 * the maximum number of blocks in each transfer. The default bpt value is
 * (64 * 1024 * 1024 / bs) or 1 if the first expression is 0. That is an
 * integer division (rounds toward 0). For example if "bs=512" and "bpt=32"
 * are given then a maximum of 32 blocks (16KB in this case) are transferred
 * to or from the sg device in a single SCSI command.
 *
 * BEWARE: If the 'of' file is a 'sg' device (eg a disk) then it _will_
 * be written to, potentially destroying its previous contents.
 *
 * This version should compile with Linux sg drivers with version numbers
 * >= 30000 . Also this version also allows SIGPOLL or a RT signal to be
 * chosen. SIGIO is a synonym for SIGPOLL; SIGIO seems to be deprecated.
 */

/* We need F_SETSIG, (signal redirect), so following define */
#define _GNU_SOURCE 1

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>           /* for mmap() system call */
#include <sys/eventfd.h>
#include <sys/epoll.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifndef HAVE_LINUX_SG_V4_HDR
/* Kernel uapi header contain __user decorations on user space pointers
 * to indicate they are unsafe in the kernel space. However glibc takes
 * all those __user decorations out from headers in /usr/include/linux .
 * So to stop compile errors when directly importing include/uapi/scsi/sg.h
 * undef __user before doing that include. */
#define __user

/* Want to block the original sg.h header from also being included. That
 * causes lots of multiple definition errors. This will only work if this
 * header is included _before_ the original sg.h header.  */
#define _SCSI_GENERIC_H         /* original kernel header guard */
#define _SCSI_SG_H              /* glibc header guard */

#include "uapi_sg.h"    /* local copy of include/uapi/scsi/sg.h */

#else
#define __user
#endif  /* end of: ifndef HAVE_LINUX_SG_V4_HDR */

#include "sg_lib.h"
#include "sg_linux_inc.h"
#include "sg_io_linux.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"


static const char * version_str = "4.21 20211006";
static const char * my_name = "sgs_dd";

#ifndef SGV4_FLAG_HIPRI
#define SGV4_FLAG_HIPRI 0x800
#endif

#define DEF_BLOCK_SIZE 512
#define DEF_BPT_TIMES_BS_SZ (64 * 1024) /* 64 KB */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 40000       /* 40,000 millisecs == 40 seconds */
#define S_RW_LEN 10             /* Use SCSI READ(10) and WRITE(10) */
#define SGQ_MAX_RD_AHEAD 32
#define SGQ_MAX_WR_AHEAD 32
#define SGQ_NUM_ELEMS (SGQ_MAX_RD_AHEAD + SGQ_MAX_WR_AHEAD + 1)

#define SGQ_FREE 0
#define SGQ_IO_STARTED 1
#define SGQ_IO_FINISHED 2
#define SGQ_IO_ERR 3
#define SGQ_IO_WAIT 4

#define SGQ_CAN_DO_NOTHING 0    /* only temporarily in use */
#define SGQ_CAN_READ 1
#define SGQ_CAN_WRITE 2
#define SGQ_TIMEOUT 4

#define DEF_SIGTIMEDWAIT_USEC 100


#define STR_SZ 1024
#define INOUTF_SZ 900
#define EBUFF_SZ 1024

struct flags_t {
    bool dio;
    bool evfd;
    bool excl;
    bool hipri;
    bool immed;
    bool mmap;
    bool noxfer;
    bool pack;
    bool tag;
    bool v3;
    bool v4;
    bool given_v3v4;
};

typedef struct request_element
{
    struct request_element * nextp;
    bool stop_after_wr;
    bool wr;
    int state;
    int blk;
    int num_blks;
    uint8_t * buffp;
    uint8_t * free_buffp;
    sg_io_hdr_t io_hdr;
    struct sg_io_v4 io_v4;
    struct flags_t * iflagp;
    struct flags_t * oflagp;
    uint8_t cmd[S_RW_LEN];
    uint8_t sb[SENSE_BUFF_LEN];
    int result;
} Rq_elem;

typedef struct request_collection
{
    bool in_is_sg;
    bool out_is_sg;
    bool no_sig;
    bool use_rt_sig;
    bool both_mmap;
    int infd;
    int in_evfd;
    int in_blk;                 /* most recent read */
    int in_count;               /* most recent read */
    int in_done_count;          /* count of completed in blocks */
    int in_partial;
    int outfd;
    int out_evfd;
    int lowest_seek;
    int out_blk;                /* most recent write */
    int out_count;              /* most recent write */
    int out_done_count;         /* count of completed out blocks */
    int out_partial;
    int bs;
    int bpt;
    int dio_incomplete;
    int sum_of_resids;
    int poll_ms;
    int pollerr_count;
    int debug;                  /* also set with -v up to -vvvvv */
    sigset_t blocked_sigs;
    int sigs_waiting;
    int sigs_rt_received;
    int sigs_io_received;
    int blk_poll_count;
    Rq_elem * rd_posp;
    Rq_elem * wr_posp;
    uint8_t * in_mmapp;
    uint8_t * out_mmapp;
    struct flags_t iflag;
    struct flags_t oflag;
    Rq_elem elem[SGQ_NUM_ELEMS];
} Rq_coll;

static bool sgs_old_sg_driver = false;  /* true if VERSION_NUM < 4.00.00 */
static bool sgs_full_v4_sg_driver = false; /* set if VERSION_NUM >= 4.00.30 */
static bool sgs_nanosec_unit = false;

static int sgq_rd_ahead_lim = SGQ_MAX_RD_AHEAD;
static int sgq_wr_ahead_lim = SGQ_MAX_WR_AHEAD;
static int sgq_num_elems = (SGQ_MAX_RD_AHEAD + SGQ_MAX_WR_AHEAD + 1);


static void
usage(int pg_num)
{
    if (pg_num > 1)
        goto second_page;
    printf("Usage: "
           "sgs_dd  [bpt=BPT] [bs=BS] [count=NUM] [deb=DEB] [if=IFILE]\n"
           "               [iflag=FLAGS] [no_sig=0|1] [of=OFILE] "
           "[oflag=FLAGS]\n"
           "               [poll_ms=MS] [rt_sig=0|1] [seek=SEEK] "
           "[skip=SKIP]\n"
           "               [--help] [--version]\n"
           "where:\n"
           "  bpt      blocks_per_transfer (default: 65536/bs (or 128 for "
           "bs=512))\n"
           "  bs       must be the logical block size of device (def: 512)\n"
           "  deb      debug: 0->no debug (def); > 0 -> more debug\n"
           "           -v (up to -vvvvv) sets deb value to number of 'v's\n"
           "  iflag    comma separated list from: dio,evfd,excl,hipri,immed,"
           "mmap\n"
           "           noxfer,null,pack,tag,v3,v4 bound to IFILE\n"
           "  no_sig   0-> use signals; 1-> no signals, hard polling "
           "instead;\n"
           "           default 0, unless hipri flag(s) given then it's 1\n"
           "  oflag    same flags as iflag but bound to OFILE\n"
           "  poll_ms    number of milliseconds to wait on poll (def: 0)\n"
           "  rt_sig   0->use SIGIO (def); 1->use RT sig (SIGRTMIN + 1)\n"
           "  <other operands>     as per dd command\n\n");
    printf("dd clone for testing Linux sg driver SIGPOLL and/or polling. "
           "Either\nIFILE or OFILE must be a scsi generic device. If OFILE "
           "not given then\n/dev/null assumed (rather than stdout like "
           "dd). Use '-hh' for flag\ninformation.\n");
    return;
second_page:
    printf("flag description:\n"
           "  dio      this driver's version of O_DIRECT\n"
           "  evfd     when poll() gives POLLIN, use eventfd to find "
           "out how many\n"
           "  excl     open IFILE or OFILE with O_EXCL\n"
           "  hipri    set HIPRI flag and use blk_poll() for completion\n"
           "  immed    use SGV4_FLAG_IMMED flag on each request\n"
           "  mmap     use mmap()-ed IO on IFILE or OFILE\n"
           "  noxfer    no transfer between user space and kernel IO "
           "buffers\n"
           "  null      does nothing, placeholder\n"
           "  pack      submit with rising pack_id, complete matching "
           "each pack_id\n"
           "  tag       use tag (from block layer) rather than "
           "pack_id\n"
           "  v3        use sg v3 interface (default)\n"
           "  v4        use sg vr interface (i.e. struct sg_io_v4)\n");
}

static int
get_mmap_addr(int fd, int num, uint8_t ** mmpp)
{
    uint8_t * mmp;

    if (! mmpp)
        return -EINVAL;
    mmp = (uint8_t *)mmap(NULL, num, PROT_READ | PROT_WRITE,
                          MAP_SHARED, fd, 0);
    if (MAP_FAILED == mmp) {
        int err = errno;

        pr2serr("%s%s: sz=%d, fd=%d, mmap() failed: %s\n",
                my_name, __func__, num, fd, strerror(err));
        return -err;
    }
    *mmpp = mmp;
    return 0;
}

/* Return of 0 -> success, -1 -> failure, 2 -> try again */
static int
read_capacity(int sg_fd, int * num_sect, int * sect_sz)
{
    int res;
    uint8_t rcCmdBlk [10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t rcBuff[64];
    uint8_t sense_b[64];
    sg_io_hdr_t io_hdr;

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(rcBuff);
    io_hdr.dxferp = rcBuff;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        res = -errno;
        perror("read_capacity (SG_IO) error");
        return res;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_LIB_CAT_UNIT_ATTENTION == res)
        return 2; /* probably have another go ... */
    else if (SG_LIB_CAT_CLEAN != res) {
        sg_chk_n_print3("read capacity", &io_hdr, true);
        return -1;
    }
    *num_sect = sg_get_unaligned_be32(rcBuff + 0) + 1;
    *sect_sz = sg_get_unaligned_be32(rcBuff + 4);
    return 0;
}

/* -ve -> unrecoverable error, 0 -> successful, 1 -> recoverable (ENOMEM) */
static int
sg_start_io(Rq_coll * clp, Rq_elem * rep)
{
    bool is_wr = rep->wr;
    int res;
    int fd = is_wr ? clp->outfd : clp->infd;
    int num_bytes = clp->bs * rep->num_blks;
    struct flags_t * flagp = is_wr ? rep->oflagp : rep->iflagp;
    sg_io_hdr_t * hp = &rep->io_hdr;
    struct sg_io_v4 * h4p = &rep->io_v4;

    if (clp->both_mmap && is_wr)
        memcpy(clp->out_mmapp, clp->in_mmapp, num_bytes);
    memset(rep->cmd, 0, sizeof(rep->cmd));
    rep->cmd[0] = is_wr ? 0x2a : 0x28;
    sg_put_unaligned_be32((uint32_t)rep->blk, rep->cmd + 2);
    sg_put_unaligned_be16((uint16_t)rep->num_blks, rep->cmd + 7);
    if (flagp->v4)
        goto do_v4;

    memset(hp, 0, sizeof(sg_io_hdr_t));
    hp->interface_id = 'S';
    hp->cmd_len = sizeof(rep->cmd);
    hp->cmdp = rep->cmd;
    hp->dxfer_direction = is_wr ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    hp->dxfer_len = num_bytes;
    hp->mx_sb_len = sizeof(rep->sb);
    hp->sbp = rep->sb;
    hp->timeout = DEF_TIMEOUT;
    hp->usr_ptr = rep;
    hp->pack_id = rep->blk;
    if (flagp->dio)
        hp->flags |= SG_FLAG_DIRECT_IO;
    if (flagp->hipri)
        hp->flags |= SGV4_FLAG_HIPRI;
    if (flagp->noxfer)
        hp->flags |= SG_FLAG_NO_DXFER;
    if (flagp->immed)
        hp->flags |= SGV4_FLAG_IMMED;
    if (flagp->mmap) {
        hp->flags |= SG_FLAG_MMAP_IO;
        hp->dxferp = is_wr ? clp->out_mmapp : clp->in_mmapp;
    } else
        hp->dxferp = rep->buffp;
    if (flagp->evfd)
        hp->flags |= SGV4_FLAG_EVENTFD;
    if (clp->debug > 5) {
        pr2serr("%s: SCSI %s, blk=%d num_blks=%d\n", __func__,
                is_wr ? "WRITE" : "READ", rep->blk, rep->num_blks);
        sg_print_command(hp->cmdp);
        pr2serr("dir=%d, len=%d, dxfrp=%p, cmd_len=%d\n", hp->dxfer_direction,
                hp->dxfer_len, hp->dxferp, hp->cmd_len);
    }

    while (((res = write(fd, hp, sizeof(sg_io_hdr_t))) < 0) &&
           (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        if ((EDOM == errno) || (EAGAIN == errno) || (EBUSY == errno)) {
            rep->state = SGQ_IO_WAIT;   /* busy so wait */
            return 0;
        }
        pr2serr("%s: write(): %s [%d]\n", __func__, strerror(errno), errno);
        rep->state = SGQ_IO_ERR;
        return res;
    }
    rep->state = SGQ_IO_STARTED;
    if (! clp->no_sig)
        clp->sigs_waiting++;
    return 0;
do_v4:
    memset(h4p, 0, sizeof(struct sg_io_v4));
    h4p->guard = 'Q';
    h4p->request_len = sizeof(rep->cmd);
    h4p->request = (uint64_t)(uintptr_t)rep->cmd;
    if (is_wr)
        h4p->dout_xfer_len = num_bytes;
    else if (rep->num_blks > 0)
        h4p->din_xfer_len = num_bytes;
    h4p->max_response_len = sizeof(rep->sb);
    h4p->response = (uint64_t)(uintptr_t)rep->sb;
    h4p->timeout = DEF_TIMEOUT;
    h4p->usr_ptr = (uint64_t)(uintptr_t)rep;
    h4p->request_extra = rep->blk;/* N.B. blk --> pack_id --> request_extra */
    if (flagp->dio)
        h4p->flags |= SG_FLAG_DIRECT_IO;
    if (flagp->noxfer)
        h4p->flags |= SG_FLAG_NO_DXFER;
    if (flagp->hipri)
        h4p->flags |= SGV4_FLAG_HIPRI;
    if (flagp->immed)
        h4p->flags |= SGV4_FLAG_IMMED;
    if (flagp->mmap) {
        h4p->flags |= SG_FLAG_MMAP_IO;
        hp->dxferp = is_wr ? clp->out_mmapp : clp->in_mmapp;
    } else {
        if (is_wr)
            h4p->dout_xferp = (uint64_t)(uintptr_t)rep->buffp;
        else if (rep->num_blks > 0)
            h4p->din_xferp = (uint64_t)(uintptr_t)rep->buffp;
    }
    if (flagp->tag)
        h4p->flags |= SGV4_FLAG_YIELD_TAG;
    if (flagp->evfd)
        h4p->flags |= SGV4_FLAG_EVENTFD;
    if (! clp->no_sig)
        h4p->flags |= SGV4_FLAG_SIGNAL;

    while (((res = ioctl(fd, SG_IOSUBMIT, h4p)) < 0) && (EINTR == errno))
        ;
    if (res < 0) {
        if (ENOMEM == errno)
            return 1;
        if ((EDOM == errno) || (EAGAIN == errno) || (EBUSY == errno)) {
            rep->state = SGQ_IO_WAIT;   /* busy so wait */
            return 0;
        }
        pr2serr("%s: ioctl(SG_IOSUBMIT): %s [%d]\n", __func__,
                strerror(errno), errno);
        rep->state = SGQ_IO_ERR;
        return res;
    }
    rep->state = SGQ_IO_STARTED;
    if (! clp->no_sig)
        clp->sigs_waiting++;
    if (clp->debug > 5) {
        if (is_wr ? clp->oflag.tag : clp->iflag.tag)
            pr2serr("%s:  generated_tag=0x%" PRIx64 "\n", __func__,
                    (uint64_t)h4p->generated_tag);
    }
    return 0;
}

/* -1 -> unrecoverable error, 0 -> successful, 1 -> try again */
static int
sg_finish_io(Rq_coll * clp, bool wr, Rq_elem ** repp)
{
    struct flags_t *flagsp = wr ? &clp->oflag : &clp->iflag;
    bool dio = false;
    bool is_v4 = flagsp->v4;
    bool use_pack = flagsp->pack;
    bool use_tag = flagsp->tag;
    int fd = wr ? clp->outfd : clp->infd;
    int res, id, n;
    sg_io_hdr_t io_hdr;
    sg_io_hdr_t * hp;
    struct sg_io_v4 io_v4;
    struct sg_io_v4 * h4p;
    Rq_elem * rep;

    if (is_v4)
        goto do_v4;
    if (use_pack) {
        while (true) {
            if ( ((res = ioctl(fd, SG_GET_NUM_WAITING, &n))) < 0) {
                res = -errno;
                pr2serr("%s: ioctl(SG_GET_NUM_WAITING): %s [%d]\n",
                        __func__, strerror(errno), errno);
                return res;
            }
            if (n > 0) {
                if ( (ioctl(fd, SG_GET_PACK_ID, &id)) < 0) {
                    res = errno;
                    pr2serr("%s: ioctl(SG_GET_PACK_ID): %s [%d]\n",
                            __func__, strerror(res), res);
                    return -res;
                }
                /* got pack_id or tag of first waiting */
                break;
            }
        }
    }
    memset(&io_hdr, 0 , sizeof(sg_io_hdr_t));
    if (use_pack)
        io_hdr.pack_id = id;
    while (((res = read(fd, &io_hdr, sizeof(sg_io_hdr_t))) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    rep = (Rq_elem *)io_hdr.usr_ptr;
    if (rep) {
        dio = flagsp->dio;
        if (rep->io_hdr.flags & SGV4_FLAG_HIPRI)
            ++clp->blk_poll_count;
    }
    if (res < 0) {
        res = -errno;
        pr2serr("%s: read(): %s [%d]\n", __func__, strerror(errno), errno);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return res;
    }
    if (! (rep && (SGQ_IO_STARTED == rep->state))) {
        pr2serr("%s: bad usr_ptr\n", __func__);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return -1;
    }
    memcpy(&rep->io_hdr, &io_hdr, sizeof(sg_io_hdr_t));
    hp = &rep->io_hdr;
    if (repp)
        *repp = rep;

    switch (sg_err_category3(hp)) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            pr2serr("Recovered error on block=%d, num=%d\n", rep->blk,
                    rep->num_blks);
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            return 1;
        default:
            sg_chk_n_print3(wr ? "writing": "reading", hp, true);
            rep->state = SGQ_IO_ERR;
            return -1;
    }
    if (dio && ((hp->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        ++clp->dio_incomplete; /* count dios done as indirect IO */
    clp->sum_of_resids += hp->resid;
    rep->state = SGQ_IO_FINISHED;
    if (clp->debug > 5) {
        pr2serr("%s: %s  ", __func__, wr ? "writing" : "reading");
        pr2serr("    SGQ_IO_FINISHED elem idx=%zd\n", rep - clp->elem);
    }
    return 0;
do_v4:
    id = -1;
    if (use_pack || use_tag) {
        while (true) {
            if ( ((res = ioctl(fd, SG_GET_NUM_WAITING, &n))) < 0) {
                res = -errno;
                pr2serr("%s: ioctl(SG_GET_NUM_WAITING): %s [%d]\n",
                        __func__, strerror(errno), errno);
                return res;
            }
            if (n > 0) {
                if ( (ioctl(fd, SG_GET_PACK_ID, &id)) < 0) {
                    res = errno;
                    pr2serr("%s: ioctl(SG_GET_PACK_ID): %s [%d]\n",
                            __func__, strerror(res), res);
                    return -res;
                }
                /* got pack_id or tag of first waiting */
                break;
            }
        }
    }
    memset(&io_v4, 0 , sizeof(io_v4));
    io_v4.guard = 'Q';
    if (use_tag)
        io_v4.request_tag = id;
    else if (use_pack)
        io_v4.request_extra = id;
    io_v4.flags |= SGV4_FLAG_IMMED;
    if (flagsp->evfd)
        io_v4.flags |= SGV4_FLAG_EVENTFD;
    while (((res = ioctl(fd, SG_IORECEIVE, &io_v4)) < 0) &&
           ((EINTR == errno) || (EAGAIN == errno) || (EBUSY == errno)))
        ;
    rep = (Rq_elem *)(unsigned long)io_v4.usr_ptr;
    if (res < 0) {
        res = -errno;
        pr2serr("%s: ioctl(SG_IORECEIVE): %s [%d]\n", __func__,
                strerror(errno), errno);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return res;
    }
    if (rep) {
        if (rep->io_v4.flags & SGV4_FLAG_HIPRI)
            ++clp->blk_poll_count;
    }
    if (! (rep && (SGQ_IO_STARTED == rep->state))) {
        pr2serr("%s: bad usr_ptr=0x%p\n", __func__, (void *)rep);
        if (rep)
            rep->state = SGQ_IO_ERR;
        return -1;
    }
    memcpy(&rep->io_v4, &io_v4, sizeof(struct sg_io_v4));
    h4p = &rep->io_v4;
    if (repp)
        *repp = rep;

    res = sg_err_category_new(h4p->device_status, h4p->transport_status,
                              h4p->driver_status,
                      (const uint8_t *)(unsigned long)h4p->response,
                              h4p->response_len);
    switch (res) {
        case SG_LIB_CAT_CLEAN:
            break;
        case SG_LIB_CAT_RECOVERED:
            pr2serr("Recovered error on block=%d, num=%d\n", rep->blk,
                    rep->num_blks);
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            return 1;
        default:
            sg_linux_sense_print(wr ? "writing": "reading",
                                 h4p->device_status, h4p->transport_status,
                                 h4p->driver_status,
                         (const uint8_t *)(unsigned long)h4p->response,
                                 h4p->response_len, true);
            rep->state = SGQ_IO_ERR;
            return -1;
    }
    if (dio && ((h4p->info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        ++clp->dio_incomplete; /* count dios done as indirect IO */
    clp->sum_of_resids += h4p->din_resid;
    rep->state = SGQ_IO_FINISHED;
    if (clp->debug > 5) {
        pr2serr("%s: %s  ", __func__, wr ? "writing" : "reading");
        pr2serr("    SGQ_IO_FINISHED elem idx=%zd\n", rep - clp->elem);
        if (use_pack)
            pr2serr("%s:  pack_id=%d\n", __func__, h4p->request_extra);
        else if (use_tag)
            pr2serr("%s:  request_tag=0x%" PRIx64 "\n", __func__,
                    (uint64_t)h4p->request_tag);
    }
    return 0;
}

static int
sz_reserve(Rq_coll * clp, bool is_in)
{
    const struct flags_t *flagsp = is_in ? &clp->iflag : &clp->oflag;
    bool pack = flagsp->pack;
    bool vb = clp->debug;
    int res, t, flags, err;
    int fd = is_in ? clp->infd : clp->outfd;
    int tag = flagsp->tag;
    struct sg_extended_info sei;
    struct sg_extended_info * seip;

    seip = &sei;
    res = ioctl(fd, SG_GET_VERSION_NUM, &t);
    if ((res < 0) || (t < 30000)) {
        pr2serr("%s: sg driver prior to 3.0.00\n", my_name);
        return 1;
    } else if (t < 40000) {
        if (vb)
            pr2serr("%s: warning: sg driver prior to 4.0.00\n", my_name);
        sgs_old_sg_driver = true;
    } else if (t < 40045) {
        sgs_old_sg_driver = false;
        sgs_full_v4_sg_driver = false;
    } else
        sgs_full_v4_sg_driver = true;
    t = clp->bs * clp->bpt;
    res = ioctl(fd, SG_SET_RESERVED_SIZE, &t);
    if (res < 0)
        perror("sgs_dd: SG_SET_RESERVED_SIZE error");

    if (sgs_full_v4_sg_driver) {
        if (sgs_nanosec_unit) {
            memset(seip, 0, sizeof(*seip));
            seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
            seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TIME_IN_NS;
            seip->ctl_flags |= SG_CTL_FLAGM_TIME_IN_NS;
            if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
                pr2serr("ioctl(EXTENDED(TIME_IN_NS)) failed, errno=%d %s\n",
                        errno, strerror(errno));
                return 1;
            }
        }
        if (tag || pack) {
            t = 1;
            if (ioctl(fd, SG_SET_FORCE_PACK_ID, &t) < 0) {
                pr2serr("ioctl(SG_SET_FORCE_PACK_ID(on)) failed, errno=%d "
                        "%s\n", errno, strerror(errno));
                return 1;
            }
            if (tag) {
                memset(seip, 0, sizeof(*seip));
                seip->sei_wr_mask |= SG_SEIM_CTL_FLAGS;
                seip->ctl_flags_wr_mask |= SG_CTL_FLAGM_TAG_FOR_PACK_ID;
                seip->ctl_flags |= SG_CTL_FLAGM_TAG_FOR_PACK_ID;
                if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
                    pr2serr("ioctl(EXTENDED(TAG_FOR_PACK_ID)) failed, "
                            "errno=%d %s\n", errno, strerror(errno));
                    return 1;
                }
            }
        }
        if (flagsp->evfd) {
            int evfd = eventfd(0,0);

            if (evfd < 0) {
                err = errno;
                pr2serr("eventfd() failed: %s\n", strerror(err));
                return 1;
            }
            if (is_in)
                clp->in_evfd = evfd;
            else
                clp->out_evfd = evfd;

            memset(seip, 0, sizeof(*seip));
            seip->sei_wr_mask |= SG_SEIM_EVENTFD;
            seip->sei_rd_mask |= SG_SEIM_EVENTFD;
            seip->share_fd = evfd;
            if (ioctl(fd, SG_SET_GET_EXTENDED, seip) < 0) {
                err = errno;
                pr2serr("ioctl(EXTENDED(SG_SEIM_EVENTFD)) failed, "
                        "errno=%d %s\n", err, strerror(err));
                return 1;
            }
        }
    }
    if (!clp->no_sig) {
        if (-1 == fcntl(fd, F_SETOWN, getpid())) {
            perror("fcntl(F_SETOWN)");
            return 1;
        }
        flags = fcntl(fd, F_GETFL, 0);
        if (-1 == fcntl(fd, F_SETFL, flags | O_ASYNC)) {
            perror("fcntl(F_SETFL)");
            return 1;
        }
        if (clp->use_rt_sig) {/* displaces SIGIO/SIGPOLL with SIGRTMIN + 1 */
            if (-1 == fcntl(fd, F_SETSIG, SIGRTMIN + 1))
                perror("fcntl(F_SETSIG)");
        }
    }
    return 0;
}

static int
init_elems(Rq_coll * clp)
{
    bool either_mmap = false;
    int res = 0;
    int num_bytes = clp->bpt * clp->bs;
    int k;
    Rq_elem * rep;

    clp->wr_posp = &clp->elem[0]; /* making ring buffer */
    clp->rd_posp = clp->wr_posp;
    if (clp->iflag.mmap || clp->oflag.mmap) {
        int res;

        either_mmap = true;
        sgq_num_elems = 2;
        sgq_rd_ahead_lim = 1;
        sgq_wr_ahead_lim = 1;
        if (clp->iflag.mmap) {
            res = get_mmap_addr(clp->infd, num_bytes, &clp->in_mmapp);
            if (res < 0)
                return res;
        }
        if (clp->oflag.mmap) {
            res = get_mmap_addr(clp->outfd, num_bytes, &clp->out_mmapp);
            if (res < 0)
                return res;
        }
    }
    for (k = 0; k < sgq_num_elems - 1; ++k)
        clp->elem[k].nextp = &clp->elem[k + 1];
    clp->elem[sgq_num_elems - 1].nextp = &clp->elem[0];
    for (k = 0; k < sgq_num_elems; ++k) {
        rep = &clp->elem[k];
        rep->state = SGQ_FREE;
        rep->iflagp = &clp->iflag;
        rep->oflagp = &clp->oflag;
        if (either_mmap) {
            if (clp->both_mmap)
                continue;
            if (clp->iflag.mmap)
                rep->buffp = clp->in_mmapp;
            else
                rep->buffp = clp->out_mmapp;
            continue;
        }
        rep->buffp = sg_memalign(num_bytes, 0, &rep->free_buffp, false);
        if (NULL == rep->buffp) {
            pr2serr("out of memory creating user buffers\n");
            res = -ENOMEM;
        }
    }
    return res;
}

static void
remove_elems(Rq_coll * clp)
{
    Rq_elem * rep;
    int k;

    for (k = 0; k < sgq_num_elems; ++k) {
        rep = &clp->elem[k];
        if (rep->free_buffp)
            free(rep->free_buffp);
    }
}

static int
start_read(Rq_coll * clp)
{
    int blocks = (clp->in_count > clp->bpt) ? clp->bpt : clp->in_count;
    Rq_elem * rep = clp->rd_posp;
    int buf_sz, res;
    char ebuff[EBUFF_SZ];

    if (clp->debug > 5)
        pr2serr("%s: elem idx=%zd\n", __func__, rep - clp->elem);
    rep->wr = false;
    rep->blk = clp->in_blk;
    rep->num_blks = blocks;
    clp->in_blk += blocks;
    clp->in_count -= blocks;
    if (clp->in_is_sg) {
        res = sg_start_io(clp, rep);
        if (1 == res) {     /* ENOMEM, find what's available+try that */
            if (ioctl(clp->infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0) {
                res = -errno;
                perror("RESERVED_SIZE ioctls failed");
                return res;
            }
            clp->bpt = (buf_sz + clp->bs - 1) / clp->bs;
            pr2serr("Reducing blocks per transfer to %d\n", clp->bpt);
            if (clp->bpt < 1)
                return -ENOMEM;
            res = sg_start_io(clp, rep);
            if (1 == res)
                res = -ENOMEM;
        }
        if (res < 0) {
            pr2serr("%s: inputting from sg failed, blk=%d\n", my_name,
                    rep->blk);
            rep->state = SGQ_IO_ERR;
            return res;
        }
    }
    else {
        rep->state = SGQ_IO_STARTED;
        while (((res = read(clp->infd, rep->buffp, blocks * clp->bs)) < 0) &&
               (EINTR == errno))
            ;
        if (res < 0) {
            res = -errno;
            snprintf(ebuff, EBUFF_SZ, "%s: reading, in_blk=%d ", my_name,
                     rep->blk);
            perror(ebuff);
            rep->state = SGQ_IO_ERR;
            return res;
        }
        if (res < blocks * clp->bs) {
            int o_blocks = blocks;
            rep->stop_after_wr = true;
            blocks = res / clp->bs;
            if ((res % clp->bs) > 0) {
                blocks++;
                clp->in_partial++;
            }
            /* Reverse out + re-apply blocks on clp */
            clp->in_blk -= o_blocks;
            clp->in_count += o_blocks;
            rep->num_blks = blocks;
            clp->in_blk += blocks;
            clp->in_count -= blocks;
        }
        clp->in_done_count -= blocks;
        rep->state = SGQ_IO_FINISHED;
    }
    clp->rd_posp = rep->nextp;
    return blocks;
}

static int
start_write(Rq_coll * clp)
{
    Rq_elem * rep = clp->wr_posp;
    int res, blocks;
    char ebuff[EBUFF_SZ];

    while ((0 != rep->wr) || (SGQ_IO_FINISHED != rep->state)) {
        rep = rep->nextp;
        if (rep == clp->rd_posp)
            return -1;
    }
    if (clp->debug > 5)
        pr2serr("%s: elem idx=%zd\n", __func__, rep - clp->elem);
    rep->wr = true;
    blocks = rep->num_blks;
    rep->blk = clp->out_blk;
    clp->out_blk += blocks;
    clp->out_count -= blocks;
    if (clp->out_is_sg) {
        res = sg_start_io(clp, rep);
        if (1 == res)      /* ENOMEM, give up */
            return -ENOMEM;
        else if (res < 0) {
            pr2serr("%s: output to sg failed, blk=%d\n", my_name, rep->blk);
            rep->state = SGQ_IO_ERR;
            return res;
        }
    }
    else {
        rep->state = SGQ_IO_STARTED;
        while (((res = write(clp->outfd, rep->buffp,
                     rep->num_blks * clp->bs)) < 0) && (EINTR == errno))
            ;
        if (res < 0) {
            res = -errno;
            snprintf(ebuff, EBUFF_SZ, "%s: output, out_blk=%d ", my_name,
                     rep->blk);
            perror(ebuff);
            rep->state = SGQ_IO_ERR;
            return res;
        }
        if (res < blocks * clp->bs) {
            blocks = res / clp->bs;
            if ((res % clp->bs) > 0) {
                blocks++;
                clp->out_partial++;
            }
            rep->num_blks = blocks;
        }
        rep->state = SGQ_IO_FINISHED;
    }
    return blocks;
}

/* Returns 0 if SIGIO/SIGPOLL or (SIGRTMIN + 1) received, else returns negated
 * errno value; -EAGAIN for timeout. */
static int
do_sigwait(Rq_coll * clp, bool inc1_clear0)
{
    siginfo_t info;
    struct timespec ts;

    if (clp->debug > 9)
        pr2serr("%s: inc1_clear0=%d\n", __func__, (int)inc1_clear0);
    ts.tv_sec = 0;
    ts.tv_nsec = DEF_SIGTIMEDWAIT_USEC * 1000;
    while (sigtimedwait(&clp->blocked_sigs, &info, &ts) < 0) {
        int err = errno;

        if (EINTR != err) {

            if (EAGAIN != err)
                pr2serr("%s: sigtimedwait(): %s [%d]\n", __func__,
                        strerror(err), err);
            return -err;        /* EAGAIN is timeout error */
        }
    }
    if ((SIGRTMIN + 1) == info.si_signo) {
        if (inc1_clear0) {
            clp->sigs_waiting--;
            clp->sigs_rt_received++;
        } else
            clp->sigs_waiting = 0;
    } else if (SIGPOLL == info.si_signo) {
        if (inc1_clear0) {
            clp->sigs_waiting--;
            clp->sigs_io_received++;
        } else
            clp->sigs_waiting = 0;
    } else {
        pr2serr("%s: sigwaitinfo() returned si_signo=%d\n",
                __func__, info.si_signo);
        return -EINVAL;
    }
    return 0;
}

/* Returns 1 (or more) on success (found), 0 on not found, -1 on error. */
static int
do_num_poll_in(Rq_coll * clp, int fd, bool is_evfd)
{
    int err, res;
    struct pollfd a_pollfd = {0, POLLIN | POLLOUT, 0};

    if (! clp->no_sig) {
        if (clp->sigs_waiting) {
            int res = do_sigwait(clp, true);

            if ((res < 0) && (-EAGAIN != res))
                return res;
        }
    }
    a_pollfd.fd = fd;
    if (poll(&a_pollfd, 1, clp->poll_ms) < 0) {
        err = errno;
        pr2serr("%s: poll(): %s [%d]\n", __func__, strerror(err), err);
        return -err;
    }
    /* pr2serr("%s: revents=0x%x\n", __func__, a_pollfd.revents); */
    if (a_pollfd.revents & POLLIN) {
        if (is_evfd) {
            uint64_t count;

            if ((res = read(fd, &count, sizeof(count))) < 0) {
                err = errno;
                pr2serr("%s: read(): %s [%d]\n", __func__,
                        strerror(err), err);
                return -err;
            }
            return (res < (int)sizeof(uint64_t)) ? 0 : (int)count;
        } else
            return 1;   /* could be more but don't know without evfd */
    } else if (a_pollfd.revents & POLLERR)
        ++clp->pollerr_count;

    return 0;
}

static int
can_read_write(Rq_coll * clp)
{
    Rq_elem * rep = NULL;
    bool writeable = false;
    bool in_is_evfd = (clp->in_evfd >= 0);
    bool out_is_evfd = (clp->out_evfd >= 0);
    int res = 0;
    int reading = 0;
    int writing = 0;
    int rd_waiting = 0;
    int wr_waiting = 0;
    int sg_finished = 0;
    int num;
    int ofd = out_is_evfd ? clp->out_evfd : clp->outfd;
    int ifd= in_is_evfd ? clp->in_evfd : clp->infd;

    /* if write completion pending, then complete it + start read */
    if (clp->out_is_sg) {
        while ((res = do_num_poll_in(clp, ofd, out_is_evfd))) {
            if (res < 0)
                return res;
            num = res;
            while (--num >= 0) {
                res = sg_finish_io(clp, true /* write */, &rep);
                if (res < 0)
                    return res;
                else if (1 == res) {
                    res = sg_start_io(clp, rep);
                    if (0 != res)
                        return -1;  /* give up if any problems with retry */
                } else
                    sg_finished++;
            }
        }
        while ((rep = clp->wr_posp) && (SGQ_IO_FINISHED == rep->state) &&
               rep->wr && (rep != clp->rd_posp)) {
            rep->state = SGQ_FREE;
            clp->out_done_count -= rep->num_blks;
            clp->wr_posp = rep->nextp;
            if (rep->stop_after_wr)
                return -1;
        }
    }
    else if ((rep = clp->wr_posp) && rep->wr &&
             (SGQ_IO_FINISHED == rep->state)) {
        rep->state = SGQ_FREE;
        clp->out_done_count -= rep->num_blks;
        clp->wr_posp = rep->nextp;
        if (rep->stop_after_wr)
            return -1;
    }

    /* if read completion pending, then complete it + start maybe write */
    if (clp->in_is_sg) {
        while ((res = do_num_poll_in(clp, ifd, in_is_evfd))) {
            if (res < 0)
                return res;
            num = res;
            while (--num >= 0) {
                res = sg_finish_io(clp, false /* read */, &rep);
                if (res < 0)
                    return res;
                if (1 == res) {
                    res = sg_start_io(clp, rep);
                    if (0 != res)
                        return -1;  /* give up if any problems with retry */
                } else {
                    sg_finished++;
                    clp->in_done_count -= rep->num_blks;
                }
            }
        }
    }

    for (rep = clp->wr_posp, res = 1;
         rep && (rep != clp->rd_posp); rep = rep->nextp) {
        if (SGQ_IO_STARTED == rep->state) {
            if (rep->wr)
                ++writing;
            else {
                res = 0;
                ++reading;
            }
        }
        else if ((! rep->wr) && (SGQ_IO_FINISHED == rep->state)) {
            if (res)
                writeable = true;
        }
        else if (SGQ_IO_WAIT == rep->state) {
            res = 0;
            if (rep->wr)
                ++wr_waiting;
            else
                ++rd_waiting;
        }
        else
            res = 0;
    }
    if (clp->debug > 6) {
        if ((clp->debug > 7) || wr_waiting || rd_waiting) {
            pr2serr("%d/%d (nwb/nrb): read=%d/%d (do/wt) "
                    "write=%d/%d (do/wt) writeable=%d sg_fin=%d\n",
                    clp->out_blk, clp->in_blk, reading, rd_waiting,
                    writing, wr_waiting, (int)writeable, sg_finished);
        }
        // fflush(stdout);
    }
    if (writeable && (writing < sgq_wr_ahead_lim) && (clp->out_count > 0))
        return SGQ_CAN_WRITE;
    if ((reading < sgq_rd_ahead_lim) && (clp->in_count > 0) &&
        (0 == rd_waiting) && (clp->rd_posp->nextp != clp->wr_posp))
        return SGQ_CAN_READ;

    if (clp->out_done_count <= 0)
        return SGQ_CAN_DO_NOTHING;

    /* usleep(10000); */      /* hang about for 10 milliseconds */
    if ((! clp->no_sig) && clp->sigs_waiting) {
        res = do_sigwait(clp, false);
        if ((res < 0) && (-EAGAIN != res))
            return res;     /* wasn't timeout */
    }
    /* Now check the _whole_ buffer for pending requests */
    for (rep = clp->rd_posp->nextp; rep && (rep != clp->rd_posp);
         rep = rep->nextp) {
        if (SGQ_IO_WAIT == rep->state) {
            res = sg_start_io(clp, rep);
            if (res < 0)
                return res;
            if (res > 0)
                return -1;
            break;
        }
    }
    return SGQ_CAN_DO_NOTHING;
}

static bool
process_flags(const char * arg, struct flags_t * fp)
{
    char buff[256];
    char * cp;
    char * np;

    strncpy(buff, arg, sizeof(buff));
    buff[sizeof(buff) - 1] = '\0';
    if ('\0' == buff[0]) {
        pr2serr("no flag found, 'null' can be used as a placeholder\n");
        return false;
    }
    cp = buff;
    do {
        np = strchr(cp, ',');
        if (np)
            *np++ = '\0';
        if (0 == strcmp(cp, "dio"))
            fp->dio = true;
        else if (0 == strcmp(cp, "evfd"))
            fp->evfd = true;
        else if (0 == strcmp(cp, "excl"))
            fp->excl = true;
        else if (0 == strcmp(cp, "hipri"))
            fp->hipri = true;
        else if (0 == strcmp(cp, "immed"))
            fp->immed = true;
        else if (0 == strcmp(cp, "mmap"))
            fp->mmap = true;
        else if (0 == strcmp(cp, "noxfer"))
            fp->noxfer = true;
        else if (0 == strcmp(cp, "null"))
            ;
        else if (0 == strcmp(cp, "pack"))
            fp->pack = true;
        else if (0 == strcmp(cp, "tag"))
            fp->tag = true;
        else if (0 == strcmp(cp, "v3")) {
            fp->v3 = true;
            fp->v4 = false;
            fp->given_v3v4 = true;
        } else if (0 == strcmp(cp, "v4")) {
            fp->v3 = false;
            fp->v4 = true;
            fp->given_v3v4 = true;
        } else {
            pr2serr("unrecognised flag: %s\n", cp);
            return false;
        }
        cp = np;
    } while (cp);
    if (fp->dio && fp->mmap) {
        pr2serr(" Can't set both mmap and dio\n");
        return false;
    }
    if ((fp->dio || fp->mmap) && fp->noxfer) {
        pr2serr(" Can't have mmap or dio with noxfer\n");
        return false;
    }
    return true;
}


int
main(int argc, char * argv[])
{
    bool bs_given = false;
    bool no_sig_given = false;
    bool hipri_present;
    int skip = 0;
    int seek = 0;
    int ibs = 0;
    int obs = 0;
    int count = -1;
    int in_num_sect = 0;
    int out_num_sect = 0;
    int help_pg = 0;
    int res, k, in_sect_sz, out_sect_sz, crw, open_fl;
    char str[STR_SZ];
    char * key;
    char * buf;
    char inf[INOUTF_SZ];
    char outf[INOUTF_SZ];
    char ebuff[EBUFF_SZ];
    Rq_coll rcoll;
    Rq_coll * clp = &rcoll;

    memset(clp, 0, sizeof(*clp));
    clp->bpt = 0;
    clp->in_evfd = -1;
    clp->out_evfd = -1;
    clp->iflag.v3 = true;
    clp->oflag.v3 = true;
    inf[0] = '\0';
    outf[0] = '\0';
    if (argc < 2) {
        usage(1);
        return 1;
    }
    sgs_nanosec_unit = !!getenv("SG3_UTILS_LINUX_NANO");

    for(k = 1; k < argc; k++) {
        if (argv[k]) {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        }
        else
            continue;
        for(key = str, buf = key; *buf && *buf != '=';)
            buf++;
        if (*buf)
            *buf++ = '\0';
        if (0 == strcmp(key,"bpt"))
            clp->bpt = sg_get_num(buf);
        else if (0 == strcmp(key,"bs"))
            clp->bs = sg_get_num(buf);
        else if (0 == strcmp(key,"count"))
            count = sg_get_num(buf);
        else if (0 == strcmp(key,"deb"))
            clp->debug += sg_get_num(buf);
        else if (0 == strcmp(key,"ibs"))
            ibs = sg_get_num(buf);
        else if (strcmp(key,"if") == 0) {
            memcpy(inf, buf, INOUTF_SZ);
            inf[INOUTF_SZ - 1] = '\0';
        } else if (0 == strcmp(key, "iflag")) {
            if (! process_flags(buf, &clp->iflag)) {
                pr2serr("%s: bad argument to 'iflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (strcmp(key,"mrq") == 0)
            ;           /* do nothing */
        else if (0 == strcmp(key,"no_sig")) { /* default changes */
            clp->no_sig = !!sg_get_num(buf);
            no_sig_given = true;
        } else if (0 == strcmp(key,"obs"))
            obs = sg_get_num(buf);
        else if (strcmp(key,"of") == 0) {
            memcpy(outf, buf, INOUTF_SZ);
            outf[INOUTF_SZ - 1] = '\0';
        } else if (0 == strcmp(key, "oflag")) {
            if (! process_flags(buf, &clp->oflag)) {
                pr2serr("%s: bad argument to 'oflag='\n", my_name);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == strcmp(key,"poll_ms"))
            clp->poll_ms = sg_get_num(buf);
        else if (0 == strcmp(key,"rt_sig"))
            clp->use_rt_sig = !!sg_get_num(buf);
        else if (0 == strcmp(key,"seek"))
            seek = sg_get_num(buf);
        else if (0 == strcmp(key,"skip"))
            skip = sg_get_num(buf);
        else if (0 == strcmp(key,"time"))
            ;           /* do nothing */
        else if ((0 == strcmp(key,"-V")) || (0 == strcmp(key,"--version"))) {
            pr2serr("%s: version: %s\n", my_name, version_str);
            return 0;
        } else if (0 == strncmp(key,"-vvvvvvv", 8))
            clp->debug += 7;
        else if (0 == strncmp(key,"-vvvvvv", 7))
            clp->debug += 6;
        else if (0 == strncmp(key,"-vvvvv", 6))
            clp->debug += 5;
        else if (0 == strncmp(key,"-vvvv", 5))
            clp->debug += 4;
        else if (0 == strncmp(key,"-vvv", 4))
            clp->debug += 3;
        else if (0 == strncmp(key,"-vv", 3))
            clp->debug += 2;
        else if ((0 == strcmp(key,"--verbose")) || (0 == strncmp(key,"-v", 2)))
            ++clp->debug;
        else if (0 == strcmp(key,"-hhhh"))
            help_pg += 4;
        else if (0 == strcmp(key,"-hhh"))
            help_pg += 3;
        else if (0 == strcmp(key,"-hh"))
            help_pg += 2;
        else if ((0 == strcmp(key,"-h")) || (0 == strcmp(key,"--help")))
            ++help_pg;
        else {
            pr2serr("Unrecognized argument '%s'\n", key);
            usage(help_pg);
            return 1;
        }
    }
    if (clp->bs <= 0) {
        clp->bs = DEF_BLOCK_SIZE;
    } else
        bs_given = true;

    if (help_pg > 0) {
        usage(help_pg);
        return 0;
    }

    hipri_present = (clp->iflag.hipri || clp->oflag.hipri);
    if (no_sig_given) {
        if ((0 == clp->no_sig) && hipri_present)
            pr2serr("Warning: signalling doesn't work with hipri\n");
    } else      /* no_sig default varies: 0 normally and 1 if hipri present */
        clp->no_sig = hipri_present ? 1 : 0;

    if ((ibs && (ibs != clp->bs)) || (obs && (obs != clp->bs))) {
        pr2serr("If 'ibs' or 'obs' given must be same as 'bs'\n");
        usage(1);
        return 1;
    }
    if (clp->bpt <= 0) {
        clp->bpt = (DEF_BPT_TIMES_BS_SZ / clp->bs);
        if (0 == clp->bpt)
            clp->bpt = 1;
        if (! bs_given)
            pr2serr("Assume blocks size bs=%d [bytes] and blocks "
                    "per transfer bpt=%d\n", clp->bs, clp->bpt);
    } else if (! bs_given)
        pr2serr("Assume 'bs' (block size) of %d bytes\n", clp->bs);

    if ((skip < 0) || (seek < 0)) {
        pr2serr("%s: skip and seek cannot be negative\n", my_name);
        return 1;
    }
    if (clp->iflag.mmap && clp->oflag.mmap)
        clp->both_mmap = true;;

    if (clp->debug > 3)
        pr2serr("%s: if=%s skip=%d of=%s seek=%d count=%d\n", my_name,
                inf, skip, outf, seek, count);
    if (! clp->no_sig) {
        /* Need to block signals before SIGPOLL is enabled in sz_reserve() */
        sigemptyset(&clp->blocked_sigs);
        if (clp->use_rt_sig)
            sigaddset(&clp->blocked_sigs, SIGRTMIN + 1);
        sigaddset(&clp->blocked_sigs, SIGINT);
        sigaddset(&clp->blocked_sigs, SIGPOLL);
        sigprocmask(SIG_BLOCK, &clp->blocked_sigs, 0);
    }

    clp->infd = STDIN_FILENO;
    clp->outfd = STDOUT_FILENO;
    if (inf[0] && ('-' != inf[0])) {
        open_fl = clp->iflag.excl ? O_EXCL : 0;
        if ((clp->infd = open(inf, open_fl | O_RDONLY)) < 0) {
            snprintf(ebuff, EBUFF_SZ, "%s: could not open %s for reading",
                     my_name, inf);
            perror(ebuff);
            return 1;
        }
        if (ioctl(clp->infd, SG_GET_TIMEOUT, 0) < 0) {
            clp->in_is_sg = false;
            if (skip > 0) {
                off_t offset = skip;

                offset *= clp->bs;       /* could overflow here! */
                if (lseek(clp->infd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ, "%s: couldn't skip to required "
                                              "position on %s", my_name, inf);
                    perror(ebuff);
                    return 1;
                }
            }
        } else { /* looks like sg device so close then re-open it RW */
            close(clp->infd);
            open_fl = clp->iflag.excl ? O_EXCL : 0;
            open_fl |= (O_RDWR | O_NONBLOCK);
            if ((clp->infd = open(inf, open_fl)) < 0) {
                pr2serr("If %s is a sg device, need read+write "
                        "permissions, even to read it!\n", inf);
                return 1;
            }
            clp->in_is_sg = true;
            if (sz_reserve(clp, true /* is_in */))
                return 1;
            if (sgs_old_sg_driver && (clp->iflag.v4 || clp->oflag.v4)) {
                pr2serr("Unable to implement v4 flag because sg driver too "
                        "old\n");
                return 1;
            }
        }
    }
    if (outf[0] && ('-' != outf[0])) {
        open_fl = clp->oflag.excl ? O_EXCL : 0;
        open_fl |= (O_RDWR | O_NONBLOCK);
        if ((clp->outfd = open(outf, open_fl)) >= 0) {
            if (ioctl(clp->outfd, SG_GET_TIMEOUT, 0) < 0) {
                /* not a scsi generic device so now try and open RDONLY */
                close(clp->outfd);
                clp->outfd = -1;
            }
            else {
                clp->out_is_sg = true;
                if (sz_reserve(clp, false /* hence ! is_in */))
                    return 1;
                if (sgs_old_sg_driver && (clp->iflag.v4 || clp->oflag.v4)) {
                    pr2serr("Unable to implement v4 flag because sg driver "
                            "too old\n");
                    return 1;
                }
            }
        }
        if (! clp->out_is_sg) {
            if (clp->outfd >= 0) {
                close(clp->outfd);
                clp->outfd = -1;
            }
            open_fl = clp->oflag.excl ? O_EXCL : 0;
            open_fl |= (O_WRONLY | O_CREAT);
            if ((clp->outfd = open(outf, open_fl, 0666)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         "%s: could not open %s for writing", my_name, outf);
                perror(ebuff);
                return 1;
            }
            else if (seek > 0) {
                off_t offset = seek;

                offset *= clp->bs;       /* could overflow here! */
                if (lseek(clp->outfd, offset, SEEK_SET) < 0) {
                    snprintf(ebuff, EBUFF_SZ, "%s: couldn't seek to required "
                             "position on %s", my_name, outf);
                    perror(ebuff);
                    return 1;
                }
            }
        }
    } else if ('\0' == outf[0]) {
        if (STDIN_FILENO == clp->infd) {
            pr2serr("Can't have both 'if' as stdin _and_ 'of' as "
                    "/dev/null\n");
            return 1;
        }
        clp->outfd = open("/dev/null", O_RDWR);
        if (clp->outfd < 0) {
            perror("sgs_dd: could not open /dev/null");
            return 1;
        }
        clp->out_is_sg = false;
        /* ignore any seek */
    } else {    /* must be '-' for stdout */
        if (STDIN_FILENO == clp->infd) {
            pr2serr("Can't have both 'if' as stdin _and_ 'of' as stdout\n");
            return 1;
        }
    }
    if ((clp->in_is_sg || clp->out_is_sg) && !clp->iflag.given_v3v4 &&
        !clp->oflag.given_v3v4 && (clp->debug > 0)) {
        clp->iflag.v3 = true;
        pr2serr("using sg driver version 3 interface on %s\n",
                clp->in_is_sg ? inf : outf);
    }

    if (0 == count)
        return 0;
    else if (count < 0) {
        if (clp->in_is_sg) {
            res = read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
            if (2 == res) {
                pr2serr("Unit attention, media changed(in), try again\n");
                res = read_capacity(clp->infd, &in_num_sect, &in_sect_sz);
            }
            if (0 != res) {
                pr2serr("Unable to read capacity on %s\n", inf);
                in_num_sect = -1;
            } else {
                if (clp->debug > 4)
                    pr2serr("ifile: number of sectors=%d, sector size=%d\n",
                            in_num_sect, in_sect_sz);
                if (in_num_sect > skip)
                    in_num_sect -= skip;
            }
        }
        if (clp->out_is_sg) {
            res = read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
            if (2 == res) {
                pr2serr("Unit attention, media changed(out), try again\n");
                res = read_capacity(clp->outfd, &out_num_sect, &out_sect_sz);
            }
            if (0 != res) {
                pr2serr("Unable to read capacity on %s\n", outf);
                out_num_sect = -1;
            } else {
                if (clp->debug > 4)
                    pr2serr("ofile: number of sectors=%d, sector size=%d\n",
                            out_num_sect, out_sect_sz);
                if (out_num_sect > seek)
                    out_num_sect -= seek;
            }
        }
        if (clp->debug > 3)
            pr2serr("Start of loop, count=%d, in_num_sect=%d, "
                    "out_num_sect=%d\n", count, in_num_sect, out_num_sect);
        if (in_num_sect > 0) {
            if (out_num_sect > 0)
                count = (in_num_sect > out_num_sect) ? out_num_sect :
                                                       in_num_sect;
            else
                count = in_num_sect;
        }
        else
            count = out_num_sect;
    }
    if (clp->debug > 4)
        pr2serr("Start of loop, count=%d, bpt=%d\n", count, clp->bpt);

    clp->in_count = count;
    clp->in_done_count = count;
    clp->in_blk = skip;
    clp->out_count = count;
    clp->out_done_count = count;
    clp->out_blk = seek;
    res = init_elems(clp);
    if (res < 0)
        pr2serr("init_elems() failed, res=%d\n", res);
    res = 0;

/* vvvvvvvvvvvvvvvvv  Main Loop  vvvvvvvvvvvvvvvvvvvvvvvv */
    while (clp->out_done_count > 0) {
        crw = can_read_write(clp);
        if (crw < 0)
            break;
        if (SGQ_CAN_READ & crw) {
            res = start_read(clp);
            if (res <= 0) {
                pr2serr("start_read: res=%d\n", res);
                break;
            }
            res = 0;
        }
        if (SGQ_CAN_WRITE & crw) {
            res = start_write(clp);
            if (res <= 0) {
                pr2serr("start_write: res=%d\n", res);
                break;
            }
            res = 0;
        }
    }

    if ((STDIN_FILENO != clp->infd) && (clp->infd >= 0))
        close(clp->infd);
    if ((STDOUT_FILENO != clp->outfd) && (clp->outfd >= 0))
        close(clp->outfd);
    if (0 != clp->out_count) {
        pr2serr("Some error occurred, remaining blocks=%d\n", clp->out_count);
        res = 1;
    }
    pr2serr("%d+%d records in\n", count - clp->in_done_count,
            clp->in_partial);
    pr2serr("%d+%d records out\n", count - clp->out_done_count,
            clp->out_partial);
    if (clp->dio_incomplete)
        pr2serr(">> Direct IO requested but incomplete %d times\n",
                clp->dio_incomplete);
    if (clp->sum_of_resids)
        pr2serr(">> Non-zero sum of residual counts=%d\n",
                clp->sum_of_resids);
    if (clp->debug > 0) {
        if (! clp->no_sig)
            pr2serr("SIGIO/SIGPOLL signals received: %d, RT sigs: %d\n",
                    clp->sigs_io_received, clp->sigs_rt_received);
        if (hipri_present)
            pr2serr("HIPRI (blk_poll) used to complete %d commands\n",
                    clp->blk_poll_count);
    }
    if (clp->pollerr_count > 0)
        pr2serr(">> poll() system call gave POLLERR %d times\n",
                clp->pollerr_count);
    remove_elems(clp);
    return res < 0 ? 99 : res;
}
