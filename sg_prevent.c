/*
 * Copyright (c) 2004-2006 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI PREVENT ALLOW MEDIUM REMOVAL command to the
 * given SCSI device.
 */

static char * version_str = "1.03 20060125";

#define ME "sg_prevent: "


static struct option long_options[] = {
        {"allow", 0, 0, 'a'},
        {"help", 0, 0, 'h'},
        {"prevent", 1, 0, 'p'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_prevent [--allow] [--help] [--prevent=<n>] [--verbose] "
          "[--version]\n"
          "                   <scsi_device>\n"
          "  where: --allow|-a            allow media removal\n"
          "         --help|-h             print out usage message\n"
          "         --prevent=<n>|-p <n>  prevention level (def: 1 -> "
          "prevent)\n"
          "                               0 -> allow, 1 -> prevent\n"
          "                               2 -> persistent allow, 3 -> "
          "persistent prevent\n"
          "         --verbose|-v          increase verbosity\n"
          "         --version|-V          print version string and exit\n\n"
          "Performs a PREVENT ALLOW MEDIUM REMOVAL SCSI command\n"
          );

}

int main(int argc, char * argv[])
{
    int sg_fd, res, c;
    int allow = 0;
    int prevent = -1;
    int verbose = 0;
    char device_name[256];
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ahp:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            allow = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'p':
           prevent = sg_get_num(optarg);
           if ((prevent < 0) || (prevent > 3)) {
                fprintf(stderr, "bad argument to '--prevent'\n");
                return 1;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }
    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if (allow && (prevent >= 0)) {
        fprintf(stderr, "can't give both '--allow' and '--prevent='\n");
        usage();
        return 1;
    }
    if (allow)
        prevent = 0;
    else if (prevent < 0)
        prevent = 1;    /* default is to prevent, as utility name suggests */

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return 1;
    }
    res = sg_ll_prevent_allow(sg_fd, prevent, 1, verbose);
    if (0 == res)
        ret = 0;
    else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Prevent allow medium removal command not "
                "supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "Prevent allow medium removal, bad field in "
                "command\n");
    else
        fprintf(stderr, "Prevent allow medium removal command failed\n");

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, ME "close error: %s\n", safe_strerror(-res));
        return 1;
    }
    return ret;
}
