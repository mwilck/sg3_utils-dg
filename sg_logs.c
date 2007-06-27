#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2007 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI LOG SENSE command.
   
*/

static char * version_str = "0.69 20070129";    /* SPC-4 revision 8 */

#define MX_ALLOC_LEN (0xfffc)
#define SHORT_RESP_LEN 128

#define ALL_PAGE_LPAGE 0x0
#define BUFF_OVER_UNDER_LPAGE 0x1
#define WRITE_ERR_LPAGE 0x2
#define READ_ERR_LPAGE 0x3
#define READ_REV_ERR_LPAGE 0x4
#define VERIFY_ERR_LPAGE 0x5
#define NON_MEDIUM_LPAGE 0x6
#define LAST_N_ERR_LPAGE 0x7
#define LAST_N_DEFERRED_LPAGE 0xb
#define TEMPERATURE_LPAGE 0xd
#define START_STOP_LPAGE 0xe
#define APP_CLIENT_LPAGE 0xf
#define SELF_TEST_LPAGE 0x10
#define PORT_SPECIFIC_LPAGE 0x18
#define GSP_LPAGE 0x19
#define IE_LPAGE 0x2f
#define NOT_SUBPG_LOG 0x0
#define ALL_SUBPG_LOG 0xff

#define PCB_STR_LEN 128

static unsigned char rsp_buff[MX_ALLOC_LEN];

static struct option long_options[] = {
        {"all", 0, 0, 'a'},
        {"control", 1, 0, 'c'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"list", 0, 0, 'l'},
        {"maxlen", 1, 0, 'm'},
        {"name", 0, 0, 'n'},
        {"new", 0, 0, 'N'},
        {"old", 0, 0, 'O'},
        {"page", 1, 0, 'p'},
        {"paramp", 1, 0, 'P'},
        {"pcb", 0, 0, 'q'},
        {"ppc", 0, 0, 'Q'},
        {"raw", 0, 0, 'r'},
        {"reset", 0, 0, 'R'},
        {"sp", 0, 0, 's'},
        {"select", 0, 0, 'S'},
        {"temperature", 0, 0, 't'},
        {"transport", 0, 0, 'T'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_all;
    int do_help;
    int do_hex;
    int do_list;
    int do_name;
    int do_pcb;
    int do_ppc;
    int do_raw;
    int do_pcreset;
    int do_select;
    int do_sp;
    int do_temperature;
    int do_transport;
    int do_verbose;
    int do_version;
    int page_control;
    int maxlen;
    int pg_code;
    int subpg_code;
    int paramp;
    const char * device_name;
    int opt_new;
};

static void usage()
{
    printf("Usage: sg_logs [--all] [--control=PC] [--help] [--hex] "
           "[--list] [--maxlen=LEN]\n"
           "               [--name] [--page=PG[,SPG]] [--paramp=PP] [--pcb] "
           "[--ppc]\n"
           "               [--raw] [--reset] [--select] [--sp] "
           "[--temperature]\n"
           "               [--transport] [--verbose] [--version] DEVICE\n"
           "  where:\n"
           "    --all|-a        fetch and decode all log pages\n"
           "                    use twice to fetch and decode all log pages "
           "and subpages\n"
           "    --control=PC|-c PC    page control(PC) (default: 1)\n"
           "                          0: current threshhold, 1: current "
           "cumulative\n"
           "                          2: default threshhold, 3: default "
           "cumulative\n"
           "    --help|-h       print usage message then exit\n"
           "    --hex|-H        output response in hex (default: decode if "
           "known)\n"
           "    --list|-l       list supported log page names (equivalent to "
           "'-p 0')\n"
           "                    use twice to list supported log page and "
           "subpage names\n"
           "    --maxlen=LEN|-m LEN    max response length (def: 0 "
           "-> everything)\n"
           "    --name|-n       decode some pages into multiple name=value "
           "lines\n"
           "    --page=PG|-p PG    page code (in decimal)\n"
           "    --page=PG,SPG|-p PG,SPG\n"
           "                    page code plus subpage code (both default "
           "to 0)\n"
           "    --paramp=PP|-P PP    parameter pointer (decimal) (def: 0)\n"
           "    --pcb|-q        show parameter control bytes in decoded "
           "output\n");
    printf("    --ppc|-Q        set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    --raw|-r        output response in binary to stdout\n"
           "    --reset|-R      reset log parameters (takes PC and SP into "
           "account)\n"
           "                    (uses PCR bit in LOG SELECT)\n"
           "    --select|-S     perform LOG SELECT using SP and PC values\n"
           "    --sp|-s         set the Saving Parameters (SP) bit (def: 0)\n"
           "    --temperature|-t    decode temperature (log page 0xd or "
           "0x2f)\n"
           "    --transport|-T    decode transport (protocol specific port "
           "0x18) log page\n"
           "    --verbose|-v    increase verbosity\n"
           "    --version|-V    output version string then exit\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

static void usage_old()
{
    printf("Usage:  sg_logs [-a] [-A] [-c=PC] [-h] [-H] [-l] [-L] "
           "[-m=LEN] [-n]\n"
           "                [-p=PG[,SPG]] [-paramp=PP] [-pcb] [-ppc] "
           "[-r] [-select]\n"
           "                [-sp] [-t] [-T] [-v] [-V] [-?] DEVICE\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -c=PC  page control(PC) (default: 1)\n"
           "                  0: current threshhold, 1: current cumulative\n"
           "                  2: default threshhold, 3: default cumulative\n"
           "    -h     output in hex (default: decode if known)\n"
           "    -H     output in hex (same as '-h')\n"
           "    -l     list supported log page names (equivalent to "
           "'-p=0')\n"
           "    -L     list supported log page and subpages names "
           "(equivalent to\n"
           "           '-p=0,ff')\n"
           "    -m=LEN   max response length (decimal) (def: 0 "
           "-> everything)\n"
           "    -n       decode some pages into multiple name=value "
           "lines\n"
           "    -p=PG    page code in hex (def: 0)\n"
           "    -p=PG,SPG    both in hex, (defs: 0,0)\n"
           "    -paramp=PP   (in hex) (def: 0)\n"
           "    -pcb   show parameter control bytes in decoded "
           "output\n");
    printf("    -ppc   set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    -r     reset log parameters (takes PC and SP into "
           "account)\n"
           "           (uses PCR bit in LOG SELECT)\n"
           "    -select  perform LOG SELECT using SP and PC values\n"
           "    -sp    set the Saving Parameters (SP) bit (def: 0)\n"
           "    -t     outputs temperature log page (0xd)\n"
           "    -T     outputs transport (protocol specific port) log "
           "page (0x18)\n"
           "    -v     increase verbosity\n"
           "    -V     output version string\n"
           "    -?     output this usage message\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

static void usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

/* Trying to decode multipliers as sg_get_num() [as sg_libs does] would
 * only confuse things here, so use this local trimmed version */
static int get_num(const char * buf)
{
    int res, len, num;
    unsigned int unum;
    const char * commap;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    commap = strchr(buf + 1, ',');
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%x", &unum);
        num = unum;
    } else if (commap && ('H' == toupper(*(commap - 1)))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else if ((NULL == commap) && ('H' == toupper(buf[len - 1]))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%d", &num);
    if (1 == res)
        return num;
    else
        return -1;
}

static int process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n, nn;
    char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aAc:hHlLm:nNOp:P:qQrRsStTvV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++optsp->do_all;
            break;
        case 'A':
            optsp->do_all += 2;
            break;
        case 'c':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                fprintf(stderr, "bad argument to '--control='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->page_control = n;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'l':
            ++optsp->do_list;
            break;
        case 'L':
            optsp->do_list += 2;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--maxlen='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->maxlen = n;
            break;
        case 'n':
            ++optsp->do_name;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            cp = strchr(optarg, ',');
            n = get_num(optarg);
            if ((n < 0) || (n > 63)) {
                fprintf(stderr, "Bad argument to '--page='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                nn = get_num(cp + 1);
                if ((nn < 0) || (nn > 255)) {
                    fprintf(stderr, "Bad second value in argument to "
                            "'--page='\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else
                nn = 0;
            optsp->pg_code = n;
            optsp->subpg_code = nn;
            break;
        case 'P':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--paramp='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->paramp = n;
            break;
        case 'q':
            ++optsp->do_pcb;
            break;
        case 'Q':
            ++optsp->do_ppc;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 'R':
            ++optsp->do_pcreset;
            ++optsp->do_select;
            break;
        case 's':
            ++optsp->do_sp;
            break;
        case 'S':
            ++optsp->do_select;
            break;
        case 't':
            ++optsp->do_temperature;
            break;
        case 'T':
            ++optsp->do_transport;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised switch code %c [0x%x]\n", c, c);
            if (optsp->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == optsp->device_name) {
            optsp->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num, n;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    ++optsp->do_all;
                    break;
                case 'A':
                    optsp->do_all += 2;
                    break;
                case 'h':
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'l':
                    ++optsp->do_list;
                    break;
                case 'L':
                    optsp->do_list += 2;
                    break;
                case 'n':
                    ++optsp->do_name;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    optsp->do_pcreset = 1;
                    optsp->do_select = 1;
                    break;
                case 't':
                    ++optsp->do_temperature;
                    break;
                case 'T':
                    ++optsp->do_transport;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                case '?':
                    ++optsp->do_help;
                    break;
                case '-':
                    ++cp;
                    jmp_out = 1;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    printf("Bad page control after '-c=' option [0..3]\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->page_control = u;
            } else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > MX_ALLOC_LEN)) {
                    printf("Bad maximum response length after '-m=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->maxlen = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        fprintf(stderr, "Bad page code value after '-p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        fprintf(stderr, "Bad sub page code value after '-p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                    optsp->subpg_code = uu;
                } else {
                    fprintf(stderr, "Bad page code, subpage code sequence "
                            "after '-p=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("paramp=", cp, 7)) {
                num = sscanf(cp + 7, "%x", &u);
                if ((1 != num) || (u > 0xffff)) {
                    printf("Bad parameter pointer after '-paramp=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->paramp = u;
            } else if (0 == strncmp("pcb", cp, 3))
                optsp->do_pcb = 1;
            else if (0 == strncmp("ppc", cp, 3))
                optsp->do_ppc = 1;
            else if (0 == strncmp("select", cp, 6))
                optsp->do_select = 1;
            else if (0 == strncmp("sp", cp, 2))
                optsp->do_sp = 1;
            else if (0 == strncmp("old", cp, 3))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        optsp->opt_new = 0;
        res = process_cl_old(optsp, argc, argv);
        if ((0 == res) && optsp->opt_new)
            res = process_cl_new(optsp, argc, argv);
    } else {
        optsp->opt_new = 1;
        res = process_cl_new(optsp, argc, argv);
        if ((0 == res) && (0 == optsp->opt_new))
            res = process_cl_old(optsp, argc, argv);
    }
    return res;
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Call LOG SENSE twice: the first time ask for 4 byte response to determine
   actual length of response; then a second time requesting the
   min(actual_len, mx_resp_len) bytes. If the calculated length for the
   second fetch is odd then it is incremented (perhaps should be made modulo
   4 in the future for SAS). Returns 0 if ok, SG_LIB_CAT_INVALID_OP for
   log_sense not supported, SG_LIB_CAT_ILLEGAL_REQ for bad field in log sense
   command, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION,
   SG_LIB_CAT_ABORTED_COMMAND and -1 for other errors. */
static int do_logs(int sg_fd, unsigned char * resp, int mx_resp_len,
                   int noisy, const struct opts_t * optsp)
{
    int actual_len;
    int res;

    memset(resp, 0, mx_resp_len);
    if ((res = sg_ll_log_sense(sg_fd, optsp->do_ppc, optsp->do_sp,
                               optsp->page_control, optsp->pg_code,
                               optsp->subpg_code, optsp->paramp,
                               resp, 4, noisy, optsp->do_verbose))) {
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            return res;
        default:
            return -1;
        }
    }
    actual_len = (resp[2] << 8) + resp[3] + 4;
    if ((0 == optsp->do_raw) && (optsp->do_verbose > 1)) {
        fprintf(stderr, "  Log sense (find length) response:\n");
        dStrHex((const char *)resp, 4, 1);
        fprintf(stderr, "  hence calculated response length=%d\n",
                actual_len);
    }
    /* Some HBAs don't like odd transfer lengths */
    if (actual_len % 2)
        actual_len += 1;
    if (actual_len > mx_resp_len)
        actual_len = mx_resp_len;
    if ((res = sg_ll_log_sense(sg_fd, optsp->do_ppc, optsp->do_sp,
                               optsp->page_control, optsp->pg_code,
                               optsp->subpg_code, optsp->paramp,
                               resp, actual_len, noisy, optsp->do_verbose))) {
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            return res;
        default:
            return -1;
        }
    }
    if ((0 == optsp->do_raw) && (optsp->do_verbose > 1)) {
        fprintf(stderr, "  Log sense response:\n");
        dStrHex((const char *)resp, actual_len, 1);
    }
    return 0;
}

static void show_page_name(int pg_code, int subpg_code,
                           struct sg_simple_inquiry_resp * inq_dat)
{
    int done;
    char b[64];

    memset(b, 0, sizeof(b));
    /* first process log pages that do not depend on peripheral type */
    if (NOT_SUBPG_LOG == subpg_code)
        snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
    else
        snprintf(b, sizeof(b) - 1, "    0x%02x,0x%02x   ", pg_code,
                 subpg_code);
    done = 1;
    if ((NOT_SUBPG_LOG == subpg_code) || (ALL_SUBPG_LOG == subpg_code)) {
        switch (pg_code) {
        case ALL_PAGE_LPAGE: printf("%sSupported log pages", b); break;
        case BUFF_OVER_UNDER_LPAGE:
            printf("%sBuffer over-run/under-run", b);
            break;
        case WRITE_ERR_LPAGE: printf("%sError counters (write)", b); break;
        case READ_ERR_LPAGE: printf("%sError counters (read)", b); break;
        case READ_REV_ERR_LPAGE:
             printf("%sError counters (read reverse)", b);
             break;
        case VERIFY_ERR_LPAGE: printf("%sError counters (verify)", b); break;
        case NON_MEDIUM_LPAGE: printf("%sNon-medium errors", b); break;
        case LAST_N_ERR_LPAGE: printf("%sLast n error events", b); break;
        case LAST_N_DEFERRED_LPAGE: printf("%sLast n deferred errors or "
                         "asynchronous events", b); break;
        case TEMPERATURE_LPAGE: printf("%sTemperature", b); break;
        case START_STOP_LPAGE: printf("%sStart-stop cycle counter", b); break;
        case APP_CLIENT_LPAGE: printf("%sApplication client", b); break;
        case SELF_TEST_LPAGE: printf("%sSelf-test results", b); break;
        case PORT_SPECIFIC_LPAGE: printf("%sProtocol specific port", b); break;
        case GSP_LPAGE:
            printf("%sGeneral statistics and performance", b);
            break;
        case IE_LPAGE: printf("%sInformational exceptions (SMART)", b); break;
        default : done = 0; break;
        }
        if (done) {
            if (ALL_SUBPG_LOG == subpg_code)
                printf(" and subpages\n");
            else
                printf("\n");
            return;
        }
    }
    if ((GSP_LPAGE == pg_code) && (subpg_code > 0) && (subpg_code < 32)) {
        printf("%sGroup statistics and performance (%d)\n", b, subpg_code);
        return;
    }
    if (subpg_code > 0) {
        printf("%s??\n", b);
        return;
    }

    done = 1;
    switch (inq_dat->peripheral_type) {
    case 0: case 4: case 7: case 0xe:
        /* disk (direct access) type devices */
        {
            switch (pg_code) {
            case 0x8:
                printf("%sFormat status (sbc-2)\n", b);
                break;
            case 0x15:
                printf("%sBackground scan results (sbc-3)\n", b);
                break;
            case 0x17:
                printf("%sNon-volatile cache (sbc-2)\n", b);
                break;
            case 0x30:
                printf("%sPerformance counters (Hitachi)\n", b);
                break;
            case 0x37:
                printf("%sCache (Seagate), Miscellaneous (Hitachi)\n", b);
                break;
            case 0x3e:
                printf("%sFactory (Seagate/Hitachi)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 1: case 2:
        /* tape (streaming) and printer (obsolete) devices */
        {
            switch (pg_code) {
            case 0xc:
                printf("%sSequential access device (ssc-2)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (ssc-3)\n", b);
                break;
            case 0x16:
                printf("%sTape diagnostic (ssc-3)\n", b);
                break;
            case 0x2e:
                printf("%sTapeAlert (ssc-2)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
    case 8:
        /* medium changer type devices */
        {
            switch (pg_code) {
            case 0x14:
                printf("%sMedia changer statistics (smc-3)\n", b);
                break;
            case 0x2e:
                printf("%sTapeAlert (smc-3)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
    case 0x12: /* Automation Device interface (ADC) */
        {
            switch (pg_code) {
            case 0x11:
                printf("%sDTD status (adc)\n", b);
                break;
            case 0x12:
                printf("%sTape alert response (adc)\n", b);
                break;
            case 0x13:
                printf("%sRequested recovery (adc)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (adc)\n", b);
                break;
            case 0x15:
                printf("%sService buffers information (adc)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }

    default: done = 0; break;
    }
    if (done)
        return;

    printf("%s??\n", b);
}

static void get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[PCB_STR_LEN];
    int n;

    n = sprintf(buff, "du=%d [ds=%d] tsd=%d etc=%d ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0), 
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "tmc=%d ", ((pcb & 0xc) >> 2));
#if 1
    n += sprintf(buff + n, "format+linking=%d  [0x%.2x]", pcb & 3,
                 pcb);
#else
    if (pcb & 0x1)
        n += sprintf(buff + n, "lbin=%d ", ((pcb & 0x2) >> 1));
    n += sprintf(buff + n, "lp=%d  [0x%.2x]", pcb & 0x1, pcb);
#endif
    if (outp && (n < maxoutlen)) {
        memcpy(outp, buff, n);
        outp[n] = '\0';
    } else if (outp && (maxoutlen > 0))
        outp[0] = '\0';
}

static void show_buffer_under_overrun_page(unsigned char * resp, int len,
                                           int show_pcb)
{
    int k, j, num, pl, count_basis, cause, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Buffer over-run/under-run page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pl = ucp[3] + 4;
        count_basis = (ucp[1] >> 5) & 0x7;
        cause = (ucp[1] >> 1) & 0xf;
        if ((0 == count_basis) && (0 == cause))
            printf("Count basis+Cause both undefined(0), unsupported??");
        else {
            printf("  Count basis: ");
            switch (count_basis) {
            case 0 : printf("undefined"); break;
            case 1 : printf("per command"); break;
            case 2 : printf("per failed reconnect"); break;
            case 3 : printf("per unit of time"); break;
            default: printf("reserved [0x%x]", count_basis); break;
            }
            printf(", Cause: ");
            switch (cause) {
            case 0 : printf("undefined"); break;
            case 1 : printf("bus busy"); break;
            case 2 : printf("transfer rate too slow"); break;
            default: printf("reserved [0x%x]", cause); break;
            }
            printf(", Type: ");
            if (ucp[1] & 1)
                printf("over-run");
            else
                printf("under-run");
            printf(", count");
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            printf(" = %" PRIu64 "", ull);
        }
        if (show_pcb) {
            pcb = ucp[2];
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_error_counter_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    switch(resp[0] & 0x3f) {
    case WRITE_ERR_LPAGE:
        printf("Write error counter page\n");
        break;
    case READ_ERR_LPAGE:
        printf("Read error counter page\n");
        break;
    case READ_REV_ERR_LPAGE:
        printf("Read Reverse error counter page\n");
        break;
    case VERIFY_ERR_LPAGE:
        printf("Verify error counter page\n");
        break;
    default:
        printf("expecting error counter page, got page = 0x%x\n", resp[0]);
        return;
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Errors corrected without substantial delay"); break;
        case 1: printf("  Errors corrected with possible delays"); break;
        case 2: printf("  Total rewrites or rereads"); break;
        case 3: printf("  Total errors corrected"); break;
        case 4: printf("  Total times correction algorithm processed"); break;
        case 5: printf("  Total bytes processed"); break;
        case 6: printf("  Total uncorrected errors"); break;
        case 0x8009: printf("  Track following errors [Hitachi]"); break;
        case 0x8015: printf("  Positioning errors [Hitachi]"); break;
        default: printf("  Reserved or vendor specific [0x%x]", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_non_medium_error_page(unsigned char * resp, int len,
                                       int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Non-medium error page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Non-medium error count"); break;
        default: 
            if (pc <= 0x7fff)
                printf("  Reserved [0x%x]", pc);
            else
                printf("  Vendor specific [0x%x]", pc);
            break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_last_n_error_page(unsigned char * resp, int len,
                                   int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No error events logged\n");
        return;
    }
    printf("Last n error events log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n error events log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Error event %d:\n", pc);
        if (pl > 4) {
            if ((pcb & 0x1) && (pcb & 0x2)) {
                printf("    [binary]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            } else if (pcb & 0x1)
                printf("    %.*s\n", pl - 4, (const char *)(ucp + 4));
            else {
                printf("    [data counter?? (LP bit should be set)]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

static void show_last_n_deferred_error_page(unsigned char * resp,
                                            int len, int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No deferred errors logged\n");
        return;
    }
    printf("Last n deferred errors log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n deferred errors log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Deferred error %d:\n", pc);
        dStrHex((const char *)ucp + 4, pl - 4, 1);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

static const char * self_test_code[] = {
    "default", "background short", "background extended", "reserved",
    "aborted background", "foreground short", "foreground extended",
    "reserved"};

static const char * self_test_result[] = {
    "completed without error", 
    "aborted by SEND DIAGNOSTIC", 
    "aborted other than by SEND DIAGNOSTIC", 
    "unknown error, unable to complete", 
    "self test completed with failure in test segment (which one unkown)", 
    "first segment in self test failed", 
    "second segment in self test failed", 
    "another segment in self test failed", 
    "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
    "reserved",
    "self test in progress"};

static void show_self_test_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, n, res, pcb;
    unsigned char * ucp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    if (num < 0x190) {
        printf("short self-test results page [length 0x%x rather than "
               "0x190 bytes]\n", num);
        return;
    }
    printf("Self-test results page\n");
    for (k = 0, ucp = resp + 4; k < 20; ++k, ucp += 20 ) {
        pcb = ucp[2];
        n = (ucp[6] << 8) | ucp[7];
        if ((0 == n) && (0 == ucp[4]))
            break;
        printf("  Parameter code = %d, accumulated power-on hours = %d\n",
               (ucp[0] << 8) | ucp[1], n);
        printf("    self-test code: %s [%d]\n",
               self_test_code[(ucp[4] >> 5) & 0x7], (ucp[4] >> 5) & 0x7);
        res = ucp[4] & 0xf;
        printf("    self-test result: %s [%d]\n",
               self_test_result[res], res);
        if (ucp[5])
            printf("    self-test number = %d\n", (int)ucp[5]);
        ull = ucp[8]; ull <<= 8; ull |= ucp[9]; ull <<= 8; ull |= ucp[10];
        ull <<= 8; ull |= ucp[11]; ull <<= 8; ull |= ucp[12];
        ull <<= 8; ull |= ucp[13]; ull <<= 8; ull |= ucp[14];
        ull <<= 8; ull |= ucp[15];
        if ((0xffffffffffffffffULL != ull) && (res > 0) && ( res < 0xf))
            printf("    address of first error = 0x%" PRIx64 "\n", ull);
        if (ucp[16] & 0xf)
            printf("    sense key = 0x%x, asc = 0x%x, asq = 0x%x",
                   ucp[16] & 0xf, ucp[17], ucp[18]);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_temperature_page(unsigned char * resp, int len, 
                                  int show_pcb, int hdr, int show_unknown)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Temperature log page\n");
        return;
    }
    if (hdr)
        printf("Temperature log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Temperature log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Current temperature = %d C", ucp[5]);
                else
                    printf("  Current temperature = <not available>");
            }
        } else if (1 == pc) {
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Reference temperature = %d C", ucp[5]);
                else
                    printf("  Reference temperature = <not available>");
            }

        } else if (show_unknown) {
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        } else
            continue;
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_Start_Stop_page(unsigned char * resp, int len, int show_pcb,
                                 int verbose)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Start-stop cycle counter log page\n");
        return;
    }
    printf("Start-stop cycle counter log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Start-stop cycle counter log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        switch (pc) {
        case 1:
            if (10 == extra)
                printf("  Date of manufacture, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            else if (verbose) {
                printf("  Date of manufacture parameter length "
                       "strange: %d\n", extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra)
                printf("  Accounting date, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            else if (verbose) {
                printf("  Accounting date parameter length strange: %d\n",
                       extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified cycle count over device lifetime "
                           "= -1");
                else
                    printf("  Specified cycle count over device lifetime "
                           "= %u", n);
            }
            break;
        case 4:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated start-stop cycles = -1");
                else
                    printf("  Accumulated start-stop cycles = %u", n);
            }
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_IE_page(unsigned char * resp, int len, int show_pcb, int full)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];
    char b[256];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Informational Exceptions log page\n");
        return;
    }
    if (full)
        printf("Informational Exceptions log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Informational Exceptions log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if (extra > 5) {
                if (full) {
                    printf("  IE asc = 0x%x, ascq = 0x%x", ucp[4], ucp[5]); 
                    if (ucp[4]) {
                        if(sg_get_asc_ascq_str(ucp[4], ucp[5], sizeof(b), b))
                            printf("\n    [%s]", b);
                    }
                }
                if (extra > 6) {
                    if (ucp[6] < 0xff)
                        printf("\n  Current temperature = %d C", ucp[6]);
                    else
                        printf("\n  Current temperature = <not available>");
                    if (extra > 7) {
                        if (ucp[7] < 0xff)
                            printf("\n  Threshold temperature = %d C  [IBM "
                                   "extension]", ucp[7]);
                        else
                            printf("\n  Treshold temperature = <not "
                                   "available>");
                     }
                }
            }
        } else if (full) {
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_sas_phy_event_info(int peis, unsigned long val,
                                    unsigned long thresh_val)
{
    switch (peis) {
    case 0:
        printf("     No event\n");
        break;
    case 0x1:
        printf("     Invalid word count: %lu\n", val);
        break;
    case 0x2:
        printf("     Running disparity error count: %lu\n", val);
        break;
    case 0x3:
        printf("     Loss of dword synchronization count: %lu\n", val);
        break;
    case 0x4:
        printf("     Phy reset problem count: %lu\n", val);
        break;
    case 0x5:
        printf("     Elasticity buffer overflow count: %lu\n", val);
        break;
    case 0x6:
        printf("     Received ERROR  count: %lu\n", val);
        break;
    case 0x20:
        printf("     Received address frame error count: %lu\n", val);
        break;
    case 0x21:
        printf("     Transmitted OPEN_REJECT abandon count: %lu\n", val);
        break;
    case 0x22:
        printf("     Received OPEN_REJECT abandon count: %lu\n", val);
        break;
    case 0x23:
        printf("     Transmitted OPEN_REJECT retry count: %lu\n", val);
        break;
    case 0x24:
        printf("     Received OPEN_REJECT retry count: %lu\n", val);
        break;
    case 0x25:
        printf("     Received AIP (PARTIAL) count: %lu\n", val);
        break;
    case 0x26:
        printf("     Received AIP (CONNECTION) count: %lu\n", val);
        break;
    case 0x27:
        printf("     Transmitted BREAK count: %lu\n", val);
        break;
    case 0x28:
        printf("     Received BREAK count: %lu\n", val);
        break;
    case 0x29:
        printf("     Break timeout count: %lu\n", val);
        break;
    case 0x2a:
        printf("     Connection count: %lu\n", val);
        break;
    case 0x2b:
        printf("     Peak transmitted pathway blocked count: %lu\n",
               val & 0xff);
        printf("         Peak value detector threshold: %lu\n",
               thresh_val & 0xff);
        break;
    case 0x2c:
        printf("     Peak transmitted arbitration wait time (us to 32767): "
               "%lu\n", val & 0xffff);
        printf("         Peak value detector threshold: %lu\n",
               thresh_val & 0xffff);
        break;
    case 0x2d:
        printf("     Peak arbitration time (us): %lu\n", val);
        printf("         Peak value detector threshold: %lu\n", thresh_val);
        break;
    case 0x2e:
        printf("     Peak connection time (us): %lu\n", val);
        printf("         Peak value detector threshold: %lu\n", thresh_val);
        break;
    case 0x40:
        printf("     Transmitted SSP frame count: %lu\n", val);
        break;
    case 0x41:
        printf("     Received SSP frame count: %lu\n", val);
        break;
    case 0x42:
        printf("     Transmitted SSP frame error count: %lu\n", val);
        break;
    case 0x43:
        printf("     Received SSP frame error count: %lu\n", val);
        break;
    case 0x44:
        printf("     Transmitted CREDIT_BLOCKED count: %lu\n", val);
        break;
    case 0x45:
        printf("     Received CREDIT_BLOCKED count: %lu\n", val);
        break;
    case 0x50:
        printf("     Transmitted SATA frame count: %lu\n", val);
        break;
    case 0x51:
        printf("     Received SATA frame count: %lu\n", val);
        break;
    case 0x52:
        printf("     SATA flow control buffer overflow count: %lu\n", val);
        break;
    case 0x60:
        printf("     Transmitted SMP frame count: %lu\n", val);
        break;
    case 0x61:
        printf("     Received SMP frame count: %lu\n", val);
        break;
    case 0x63:
        printf("     Received SMP frame error count: %lu\n", val);
        break;
    default:
        break;
    }
}

static void show_sas_rel_target_port(unsigned char * ucp, int param_len,
                                     const struct opts_t * optsp)
{
    int j, m, n, nphys, pcb, t, sz, spld_len;
    unsigned char * vcp;
    unsigned long long ull;
    unsigned long ul;
    char pcb_str[PCB_STR_LEN];
    char s[64];

    sz = sizeof(s);
    pcb = ucp[2];
    t = (ucp[0] << 8) | ucp[1];
    if (optsp->do_name)
        printf("rel_target_port=%d\n", t);
    else
        printf("relative target port id = %d\n", t);
    nphys = ucp[7];
    if (optsp->do_name)
        printf("  num_phys=%d\n", nphys);
    else {
        printf(" number of phys = %d", nphys);
        if ((optsp->do_pcb) && (0 == optsp->do_name)) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }

    for (j = 0, vcp = ucp + 8; j < (param_len - 8);
         vcp += spld_len, j += spld_len) {
        if (optsp->do_name)
            printf("    phy_id=%d\n", vcp[1]);
        else
            printf("  phy identifier = %d\n", vcp[1]);
        spld_len = vcp[3];
        if (spld_len < 44)
            spld_len = 48;
        else
            spld_len += 4;
        t = ((0x70 & vcp[4]) >> 4);
        if (optsp->do_name) {
            printf("      att_dev_type=%d\n", t);
            printf("      att_iport_mask=0x%x\n", vcp[6]);
            printf("      att_phy_id=%d\n", vcp[24]);
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("      att_sas_addr=0x%" PRIx64 "\n", ull);
            printf("      att_tport_mask=0x%x\n", vcp[7]);
            ul = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("      inv_dwords=%ld\n", ul);
            ul = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("      loss_dword_sync=%ld\n", ul);
            printf("      neg_log_lrate=%d\n", 0xf & vcp[5]);
            ul = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("      phy_reset_probs=%ld\n", ul);
            ul = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("      running_disparity=%ld\n", ul);
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
            printf("      sas_addr=0x%" PRIx64 "\n", ull);
        } else {
            switch (t) {
            case 0: snprintf(s, sz, "no device attached"); break;
            case 1: snprintf(s, sz, "end device"); break;
            case 2: snprintf(s, sz, "expander device"); break;
            case 3: snprintf(s, sz, "expander device (fanout)"); break;
            default: snprintf(s, sz, "reserved [%d]", t); break;
            }
            printf("    attached device type: %s\n", s);
            t = (0xf & vcp[5]);
            switch (t) {
            case 0: snprintf(s, sz, "phy enabled; unknown");
                         break;
            case 1: snprintf(s, sz, "phy disabled"); break;
            case 2: snprintf(s, sz, "phy enabled; speed negotiation failed");
                         break;
            case 3: snprintf(s, sz, "phy enabled; SATA spinup hold state");
                         break;
            case 4: snprintf(s, sz, "phy enabled; port selector");
                         break;
            case 5: snprintf(s, sz, "phy enabled; reset in progress");
                         break;
            case 8: snprintf(s, sz, "phy enabled; 1.5 Gbps"); break;
            case 9: snprintf(s, sz, "phy enabled; 3 Gbps"); break;
            case 0xa: snprintf(s, sz, "phy enabled; 6 Gbps"); break;
            default: snprintf(s, sz, "reserved [%d]", t); break;
            }
            printf("    negotiated logical link rate: %s\n", s);/* sas2r07 */
            printf("    attached initiator port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            printf("    attached target port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
            for (n = 0, ull = vcp[8]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[8 + n];
            }
            printf("    SAS address = 0x%" PRIx64 "\n", ull);
            for (n = 0, ull = vcp[16]; n < 8; ++n) {
                ull <<= 8; ull |= vcp[16 + n];
            }
            printf("    attached SAS address = 0x%" PRIx64 "\n", ull);
            printf("    attached phy identifier = %d\n", vcp[24]);
            ul = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("    Invalid DWORD count = %ld\n", ul);
            ul = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("    Running disparity error count = %ld\n", ul);
            ul = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("    Loss of DWORD synchronization = %ld\n", ul);
            ul = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("    Phy reset problem = %ld\n", ul);
        }
        if (spld_len > 51) {
            int num_ped, peis;
            unsigned char * xcp;
            unsigned long pvdt;

            num_ped = vcp[51];
            if (num_ped > 0) {
                if (optsp->do_name) {
                   printf("      phy_event_desc_num=%d\n", num_ped);
                   return;      /* don't decode at this stage */
                } else
                   printf("    Phy event descriptors:\n");
            }
            xcp = vcp + 52;
            for (m = 0; m < (num_ped * 12); m += 12, xcp += 12) {
                peis = xcp[3];
                ul = (xcp[4] << 24) | (xcp[5] << 16) | (xcp[6] << 8) |
                     xcp[7];
                pvdt = (xcp[8] << 24) | (xcp[9] << 16) | (xcp[10] << 8) |
                       xcp[11];
                show_sas_phy_event_info(peis, ul, pvdt);
            }
        }
    }
}

static int show_protocol_specific_page(unsigned char * resp, int len, 
                                       const struct opts_t * optsp)
{
    int k, num, param_len;
    unsigned char * ucp;

    num = len - 4;
    for (k = 0, ucp = resp + 4; k < num; ) {
        param_len = ucp[3] + 4;
        /* each phy has a 48 byte descriptor but since param_len is
           an 8 bit quantity then only the first 5 phys (of, for example,
           a 8 phy wide link) can be represented */
        if (6 != (0xf & ucp[4]))
            return 0;   /* only decode SAS log page [sas2r05a] */
        if ((0 == k) && (0 == optsp->do_name))
            printf("SAS Protocol Specific page\n");
        show_sas_rel_target_port(ucp, param_len, optsp);
        k += param_len;
        ucp += param_len;
    }
    return 1;
}

static void show_format_status_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb, all_ff, counter;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Format status page (sbc-2) [0x8]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        counter = 1;
        switch (pc) {
        case 0: printf("  Format data out:\n");
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        case 1: printf("  Grown defects during certification"); break;
        case 2: printf("  Total blocks relocated during format"); break;
        case 3: printf("  Total new blocks relocated"); break;
        case 4: printf("  Power on minutes since format"); break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (counter) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (all_ff = 0, j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                else
                    all_ff = 1;
                ull |= xp[j];
                if (0xff != xp[j])
                    all_ff = 0;
            }
            if (all_ff)
                printf(" <not available>");
            else
                printf(" = %" PRIu64 "", ull);
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            } else
                printf("\n");
        } else {
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            }
        }
        num -= pl;
        ucp += pl;
    }
}

static void show_non_volatile_cache_page(unsigned char * resp, int len,
                                         int show_pcb)
{
    int j, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    printf("Non-volatile cache page (sbc-2) [0x17]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Remaining non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<unknown>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        case 1:
            printf("  Maximum non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<reserved>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        }
        num -= pl;
        ucp += pl;
    }
}

static const char * bms_status[] = {
    "no background scans active",
    "background scan is active",
    "background pre-scan is active",
    "background scan halted due to fatal error",
    "background scan halted due to a vendor specific pattern of error",
    "background scan halted due to medium formatted without P-List",
    "background scan halted - vendor specific cause",
    "background scan halted due to temperature out of range",
    "background scan halted until BM interval timer expires", /* 8 */
};

static const char * reassign_status[] = {
    "No reassignment needed",
    "Reassignment pending receipt of Reassign command or Write command",
    "Logical block successfully reassigned",
    "Reassign status: Reserved [0x3]",
    "Reassignment failed",
    "Logical block recovered via rewrite in-place",
    "Logical block reassigned by application client, has valid data",
    "Logical block reassigned by application client, contains no valid data",
    "Logical block unsuccessfully reassigned by application client", /* 8 */
};

static void show_background_scan_results_page(unsigned char * resp, int len,
                                              int show_pcb, int verbose)
{
    int j, m, num, pl, pc, pcb;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Background scan results page (sbc-3) [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Status parameters:\n");
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 16 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 16 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Accumulated power on minutes: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [h:m  %d:%d]\n", j, (j / 60), (j % 60));
            printf("    Status: ");
            j = ucp[9];
            if (j < (int)(sizeof(bms_status) / sizeof(bms_status[0])))
                printf("%s\n", bms_status[j]);
            else
                printf("unknown [0x%x] background scan status value\n", j);
            printf("    Number of background scans performed: %d\n",
                   (ucp[10] << 8) + ucp[11]);
#ifdef SG3_UTILS_MINGW
            printf("    Background medium scan progress: %g%%\n",
                   (double)((ucp[12] << 8) + ucp[13]) * 100.0 / 65536.0);
#else
            printf("    Background medium scan progress: %.2f%%\n",
                   (double)((ucp[12] << 8) + ucp[13]) * 100.0 / 65536.0);
#endif
            break;
        default:
            printf("  Medium scan parameter # %d\n", pc);
            if ((pl < 24) || (num < 24)) {
                if (num < 24)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 24 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 24 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Power on minutes when error detected: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [%d:%d]\n", j, (j / 60), (j % 60));
            j = (ucp[8] >> 4) & 0xf;
            if (j < 
                (int)(sizeof(reassign_status) / sizeof(reassign_status[0])))
                printf("    %s\n", reassign_status[j]);
            else
                printf("    Reassign status: reserved [0x%x]\n", j);
            printf("    sense key: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                   sg_get_sense_key_str(ucp[8] & 0xf, sizeof(str), str),
                   ucp[8] & 0xf, ucp[9], ucp[10]);
            printf("      %s\n", sg_get_asc_ascq_str(ucp[9], ucp[10],
                                                     sizeof(str), str));
            if (verbose) {
                printf("    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    printf("0x%02x ", ucp[11 + m]);
                printf("\n");
            }
            printf("    LBA (associated with medium error): 0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", ucp[16 + m]);
            printf("\n");
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static void show_sequential_access_page(unsigned char * resp, int len, 
                                        int show_pcb, int verbose)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull, gbytes;
    char pcb_str[PCB_STR_LEN];

    printf("Sequential access device page (ssc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        gbytes = ull / 1000000000;
        switch (pc) {
        case 0: 
            printf("  Data bytes received with WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 1: 
            printf("  Data bytes written to media by WRITE commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 2: 
            printf("  Data bytes read from media by READ commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 3: 
            printf("  Data bytes transferred by READ commands: %" PRIu64
                   " GB", gbytes);
            if (verbose)
                printf(" [%" PRIu64 " bytes]", ull);
            printf("\n");
            break;
        case 4: 
            printf("  Native capacity from BOP to EOD: %" PRIu64 " MB\n",
                   ull);
            break;
        case 5: 
            printf("  Native capacity from BOP to EW of current partition: "
                   "%" PRIu64 " MB\n", ull);
            break;
        case 6: 
            printf("  Minimum native capacity from EW to EOP of current "
                   "partition: %" PRIu64 " MB\n", ull);
            break;
        case 7: 
            printf("  Native capacity from BOP to current position: %"
                   PRIu64 " MB\n", ull);
            break;
        case 8: 
            printf("  Maximum native capacity in device object buffer: %"
                   PRIu64 " MB\n", ull);
            break;
        case 0x100: 
            if (ull > 0)
                printf("  Cleaning action required\n");
            else
                printf("  Cleaning action not required (or completed)\n");
            if (verbose)
                printf("    cleaning value: %" PRIu64 "\n", ull);
            break;
        default:
            if (pc >= 0x8000)
                printf("  Vendor specific parameter [0x%x] value: %" PRIu64
                       "\n", pc, ull);
            else
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_device_stats_page(unsigned char * resp, int len, 
                                   int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Device statistics page (ssc-3 and adc)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (pc < 0x1000) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            switch (pc) {
            case 0: 
                printf("  Lifetime media loads: %" PRIu64 "\n", ull);
                break;
            case 1: 
                printf("  Lifetime cleaning operations: %" PRIu64 "\n", ull);
                break;
            case 2: 
                printf("  Lifetime power on hours: %" PRIu64 "\n", ull);
                break;
            case 3: 
                printf("  Lifetime media motion (head) hours: %" PRIu64 "\n",
                       ull);
                break;
            case 4: 
                printf("  Lifetime metres of tape processed: %" PRIu64 "\n",
                       ull);
                break;
            case 5: 
                printf("  Lifetime media motion (head) hours when "
                       "incompatible media last loaded: %" PRIu64 "\n", ull);
                break;
            case 6: 
                printf("  Lifetime power on hours when last temperature "
                       "condition occurred: %" PRIu64 "\n", ull);
                break;
            case 7: 
                printf("  Lifetime power on hours when last power "
                       "consumption condition occurred: %" PRIu64 "\n", ull);
                break;
            case 8: 
                printf("  Media motion (head) hours since last successful "
                       "cleaning operation: %" PRIu64 "\n", ull);
                break;
            case 9: 
                printf("  Media motion (head) hours since 2nd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xa: 
                printf("  Media motion (head) hours since 3rd to last "
                       "successful cleaning: %" PRIu64 "\n", ull);
                break;
            case 0xb: 
                printf("  Lifetime power on hours when last operator "
                       "initiated forced reset\n    and/or emergency "
                       "eject occurred: %" PRIu64 "\n", ull);
                break;
            default:
                printf("  Reserved parameter [0x%x] value: %" PRIu64 "\n",
                       pc, ull);
                break;
            }
        } else {
            switch (pc) {
            case 0x1000: 
                printf("  Media motion (head) hours for each medium type:\n");
                printf("      <<to be decoded, dump in hex for now>>:\n");
                dStrHex((const char *)ucp, pl, 0);
                break;
            default:
                printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                dStrHex((const char *)ucp, pl, 0);
                break;
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_seagate_cache_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Seagate cache page [0x37]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Blocks sent to initiator"); break;
        case 1: printf("  Blocks received from initiator"); break;
        case 2: printf("  Blocks read from cache and sent to initiator"); break;
        case 3: printf("  Number of read and write commands whose size "
                       "<= segment size"); break;
        case 4: printf("  Number of read and write commands whose size "
                       "> segment size"); break;
        default: printf("  Unknown Seagate parameter code = 0x%x", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %" PRIu64 "", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_seagate_factory_page(unsigned char * resp, int len,
                                      int show_pcb)
{
    int k, j, num, pl, pc, pcb, valid;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Seagate/Hitachi factory page [0x3e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        valid = 1;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = 0;
            printf("  Unknown Seagate/Hitachi parameter code = 0x%x", pc);
            break;
        }
        if (valid) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= xp[j];
            }
            if (0 == pc)
                printf(" = %.2f", ((double)ull) / 60.0 );
            else
                printf(" = %" PRIu64 "", ull);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_ascii_page(unsigned char * resp, int len, 
                            struct sg_simple_inquiry_resp * inq_dat,
                            const struct opts_t * optsp)
{
    int k, num, done, pg_code, subpg_code, spf;

    if (len < 0) {
        printf("response has bad length\n");
        return;
    }
    num = len - 4;
    done = 1;
    spf = !!(resp[0] & 0x40);
    pg_code = resp[0] & 0x3f;
    subpg_code = spf ? resp[1] : 0;

    if ((ALL_PAGE_LPAGE != pg_code ) && (ALL_SUBPG_LOG == subpg_code)) {
        printf("Supported subpages for log page=0x%x\n", pg_code);
        for (k = 0; k < num; k += 2)
            show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                           inq_dat);
        return;
    }
    switch (pg_code) {
    case ALL_PAGE_LPAGE:
        if (spf) {
            printf("Supported log pages and subpages:\n");
            for (k = 0; k < num; k += 2)
                show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                               inq_dat);
        } else {
            printf("Supported log pages:\n");
            for (k = 0; k < num; ++k)
                show_page_name((int)resp[4 + k], 0, inq_dat);
        }
        break;
    case BUFF_OVER_UNDER_LPAGE:
        show_buffer_under_overrun_page(resp, len, optsp->do_pcb);
        break;
    case WRITE_ERR_LPAGE:
    case READ_ERR_LPAGE:
    case READ_REV_ERR_LPAGE:
    case VERIFY_ERR_LPAGE:
        show_error_counter_page(resp, len, optsp->do_pcb);
        break;
    case NON_MEDIUM_LPAGE:
        show_non_medium_error_page(resp, len, optsp->do_pcb);
        break;
    case LAST_N_ERR_LPAGE:
        show_last_n_error_page(resp, len, optsp->do_pcb);
        break;
    case 0x8:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_format_status_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case LAST_N_DEFERRED_LPAGE:
        show_last_n_deferred_error_page(resp, len, optsp->do_pcb);
        break;
    case 0xc:
        {
            switch (inq_dat->peripheral_type) {
            case 1: case 2: case 8:
                /* tape, (printer) and medium changer type devices */
                show_sequential_access_page(resp, len, optsp->do_pcb,
                                            optsp->do_verbose);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case TEMPERATURE_LPAGE:
        show_temperature_page(resp, len, optsp->do_pcb, 1, 1);
        break;
    case START_STOP_LPAGE:
        show_Start_Stop_page(resp, len, optsp->do_pcb, optsp->do_verbose);
        break;
    case SELF_TEST_LPAGE:
        show_self_test_page(resp, len, optsp->do_pcb);
        break;
    case 0x14:
        {
            switch (inq_dat->peripheral_type) {
            case 1: case 8: case 0x12:
                /* tape, medium changer and adc type devices */
                show_device_stats_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x15:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_background_scan_results_page(resp, len, optsp->do_pcb,
                                                  optsp->do_verbose);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x17:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_non_volatile_cache_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case PORT_SPECIFIC_LPAGE:
        done = show_protocol_specific_page(resp, len, optsp);
        break;
    case IE_LPAGE:
        show_IE_page(resp, len, optsp->do_pcb, 1);
        break;
    case 0x37:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_seagate_cache_page(resp, len, optsp->do_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x3e:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_seagate_factory_page(resp, len, optsp->do_pcb);
                break;
            case 1: case 2: case 8:
                /* streaming or medium changer devices */
                /* call ssc_device_status_log_page() */
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    default:
        done = 0;
        break;
    }
    if (! done) {
        printf("No ascii information for page = 0x%x, here is hex:\n", 
               resp[0] & 0x3f);
        if (len > 128) {
            dStrHex((const char *)resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-h' to "
                   "see the rest)]\n", len);
        }
        else
            dStrHex((const char *)resp, len, 1);
    }
}
        
static int fetchTemperature(int sg_fd, unsigned char * resp, int max_len,
                            struct opts_t * optsp)
{
    int len;
    int res = 0;

    optsp->pg_code = TEMPERATURE_LPAGE;
    optsp->subpg_code = NOT_SUBPG_LOG;
    res = do_logs(sg_fd, resp, max_len, 0, optsp);
    if (0 == res) {
        len = (resp[2] << 8) + resp[3] + 4;
        if (optsp->do_raw)
            dStrRaw((const char *)resp, len);
        else if (optsp->do_hex)
            dStrHex((const char *)resp, len, 1);
        else
            show_temperature_page(resp, len, optsp->do_pcb, 0, 0);
    }else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "Device not ready\n");
    else {
        optsp->pg_code = IE_LPAGE;
        res = do_logs(sg_fd, resp, max_len, 0, optsp);
        if (0 == res) {
            len = (resp[2] << 8) + resp[3] + 4;
            if (optsp->do_raw)
                dStrRaw((const char *)resp, len);
            else if (optsp->do_hex)
                dStrHex((const char *)resp, len, 1);
            else
                show_IE_page(resp, len, 0, 0);
        } else
            fprintf(stderr, "Unable to find temperature in either log page "
                    "(temperature or IE)\n");
    }
    sg_cmds_close_device(sg_fd);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}


int main(int argc, char * argv[])
{
    int sg_fd, k, pg_len, res, resp_len;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    memset(rsp_buff, 0, sizeof(rsp_buff));
    /* N.B. some disks only give data for current cumulative */
    opts.page_control = 1; 
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 0 /* rw */,
                                     opts.do_verbose)) < 0) {
        if ((sg_fd = sg_cmds_open_device(opts.device_name, 1 /* r0 */,
                                         opts.do_verbose)) < 0) {
            fprintf(stderr, "error opening file: %s: %s \n",
                    opts.device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
    }
    if (opts.do_list || opts.do_all) {
        opts.pg_code = ALL_PAGE_LPAGE;
        if ((opts.do_list > 1) || (opts.do_all > 1))
            opts.subpg_code = ALL_SUBPG_LOG;
    }
    if (opts.do_transport) {
        if ((opts.pg_code > 0) || (opts.subpg_code > 0) ||
            opts.do_temperature) {
            fprintf(stderr, "'-T' should not be mixed with options "
                    "implying other pages\n");
            return SG_LIB_FILE_ERROR;
        }
        opts.pg_code = PORT_SPECIFIC_LPAGE;
    }
    pg_len = 0;

    if (0 == opts.do_raw) {
        if (sg_simple_inquiry(sg_fd, &inq_out, 1, opts.do_verbose)) {
            fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                    opts.device_name);
            sg_cmds_close_device(sg_fd);
            return SG_LIB_CAT_OTHER;
        } else if ((0 == opts.do_hex) && (0 == opts.do_name))
            printf("    %.8s  %.16s  %.4s\n", inq_out.vendor,
                   inq_out.product, inq_out.revision);
    } else
        memset(&inq_out, 0, sizeof(inq_out));

    if (1 == opts.do_temperature)
        return fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, &opts);

    if (opts.do_select) {
        k = sg_ll_log_select(sg_fd, !!(opts.do_pcreset), opts.do_sp,
                             opts.page_control, opts.pg_code, opts.subpg_code,
                             NULL, 0, 1, opts.do_verbose);
        if (k) {
            if (SG_LIB_CAT_NOT_READY == k)
                fprintf(stderr, "log_select: device not ready\n");
            else if (SG_LIB_CAT_INVALID_OP == k)
                fprintf(stderr, "log_select: not supported\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == k)
                fprintf(stderr, "log_select: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == k)
                fprintf(stderr, "log_select: aborted command\n");
        }
        return (k >= 0) ?  k : SG_LIB_CAT_OTHER;
    }
    resp_len = (opts.maxlen > 0) ? opts.maxlen : MX_ALLOC_LEN;
    res = do_logs(sg_fd, rsp_buff, resp_len, 1, &opts);
    if (0 == res) {
        pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
        if ((pg_len + 4) > resp_len) {
            printf("Only fetched %d bytes of response (available: %d "
                   "bytes)\n    truncate output\n",
                   resp_len, pg_len + 4);
            pg_len = resp_len - 4;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "log_sense: not supported\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "log_sense: device not ready\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "log_sense: field in cdb illegal\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "log_sense: unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "log_sense: aborted command\n");
    if (0 == opts.do_all) {
        if (opts.do_raw)
            dStrRaw((const char *)rsp_buff, pg_len + 4);
        else if (pg_len > 1) {
            if (opts.do_hex) {
                if (rsp_buff[0] & 0x40)
                    printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                           "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                           !!(rsp_buff[0] & 0x80), pg_len);
                else
                    printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                           rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
                dStrHex((const char *)rsp_buff, pg_len + 4, 1);
            }
            else
                show_ascii_page(rsp_buff, pg_len + 4, &inq_out, &opts);
        }
    }
    ret = res;

    if (opts.do_all && (pg_len > 1)) {
        int my_len = pg_len;
        int spf;
        unsigned char parr[1024];

        spf = !!(rsp_buff[0] & 0x40);
        if (my_len > (int)sizeof(parr)) {
            fprintf(stderr, "Unexpectedly large page_len=%d, trim to %d\n",
                    my_len, (int)sizeof(parr));
            my_len = sizeof(parr);
        }
        memcpy(parr, rsp_buff + 4, my_len);
        for (k = 0; k < my_len; ++k) {
            printf("\n");
            opts.pg_code = parr[k] & 0x3f;
            if (spf)
                opts.subpg_code = parr[++k];
            else
                opts.subpg_code = NOT_SUBPG_LOG;
            
            res = do_logs(sg_fd, rsp_buff, resp_len, 1, &opts);
            if (0 == res) {
                pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
                if ((pg_len + 4) > resp_len) {
                    printf("Only fetched %d bytes of response, truncate "
                           "output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (opts.do_hex) {
                    if (rsp_buff[0] & 0x40)
                        printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, page_"
                               "len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                               !!(rsp_buff[0] & 0x80), pg_len);
                    else
                        printf("Log page code=0x%x, DS=%d, SPF=0, page_len="
                               "0x%x\n", rsp_buff[0] & 0x3f,
                               !!(rsp_buff[0] & 0x80), pg_len);
                    dStrHex((const char *)rsp_buff, pg_len + 4, 1);
                }
                else
                    show_ascii_page(rsp_buff, pg_len + 4, &inq_out, &opts);
            } else if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "log_sense: page=0x%x,0x%x not supported\n",
                        opts.pg_code, opts.subpg_code);
            else if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "log_sense: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "log_sense: field in cdb illegal "
                        "[page=0x%x,0x%x]\n", opts.pg_code, opts.subpg_code);
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                fprintf(stderr, "log_sense: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                fprintf(stderr, "log_sense: aborted command\n");
        }
    }
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}
