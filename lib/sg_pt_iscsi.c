/*
 * Copyright (c) 2010 Ronnie Sahlberg
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef CONFIG_LIBISCSI

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>


#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_linux_inc.h"
#include "sg_pt_iscsi.h"

struct iscsi_lun_context {
    struct iscsi_context *context;
    int lun;
};
struct iscsi_lun_context *iscsi_contexts[ISCSI_MAX_CONTEXTS];

struct sg_pt_iscsi {
    int os_err;

    int xferdir;
    const unsigned char *cdb;
    int cdb_len;
    unsigned char *sense;
    int sense_len;
    int max_sense_len;
    struct iscsi_data datain;
    struct iscsi_data dataout;
    int device_status;
};

int
do_iscsi_pt(struct sg_pt_iscsi *iscsi, int fd, int time_secs, int verbose)
{
    struct scsi_task *task;
    struct iscsi_data *data = NULL;
    struct iscsi_lun_context *iscsi_lun = iscsi_contexts[fd & ISCSI_FAKE_FD_MASK];

    /* keep compiler happy */
    time_secs = time_secs;
    verbose   = verbose;

    task = malloc(sizeof(struct scsi_task));
    bzero(task, sizeof(struct scsi_task));

    iscsi->os_err = 0;

    task->cdb_size = iscsi->cdb_len;
    memcpy(&task->cdb[0], iscsi->cdb, task->cdb_size);

    task->xfer_dir = iscsi->xferdir;
    switch (task->xfer_dir) {
    case SCSI_XFER_NONE:
        task->expxferlen = 0;
        break;
    case SCSI_XFER_READ:
        task->expxferlen = iscsi->datain.size;
        break;
    case SCSI_XFER_WRITE:
        task->expxferlen = iscsi->dataout.size;
        data = &iscsi->dataout;
        break;
    }

    if (iscsi_scsi_command_sync(iscsi_lun->context, iscsi_lun->lun, task, data) == NULL) {
        printf("error\n");
        scsi_free_scsi_task(task);
        iscsi->os_err = -1;
        return -1;
    }

    iscsi->device_status = task->status;
    if (task->status == SCSI_STATUS_GOOD) {
        memcpy(iscsi->datain.data, task->datain.data, 
               task->datain.size<iscsi->datain.size?
                   task->datain.size:iscsi->datain.size);
        scsi_free_scsi_task(task);
        return 0;
    }

    if (task->status == SCSI_STATUS_CHECK_CONDITION) {
        /* +2 is to strip off the initial "length" and just copy the sense blob itself */
        iscsi->sense_len = (iscsi->max_sense_len<(task->datain.size-2))?iscsi->max_sense_len:(task->datain.size-2);
        memcpy(iscsi->sense,  task->datain.data+2, iscsi->sense_len);
        scsi_free_scsi_task(task);
        return 0;
    }
    return -1;
}


struct sg_pt_iscsi *
construct_iscsi_pt_obj(void)
{
    struct sg_pt_iscsi *iscsi;

    iscsi = calloc(1, sizeof(struct sg_pt_iscsi));
    iscsi->xferdir = SCSI_XFER_NONE;
    return iscsi;
}

void
clear_iscsi_pt_obj(struct sg_pt_iscsi *iscsi)
{
    if (iscsi) {
        memset(iscsi, 0, sizeof(struct sg_pt_iscsi));
        iscsi->xferdir = SCSI_XFER_READ;
    }
}

void
destruct_iscsi_pt_obj(struct sg_pt_iscsi *iscsi)
{
    if (iscsi)
        free(iscsi);
}

void
set_iscsi_pt_cdb(struct sg_pt_iscsi *iscsi, const unsigned char *cdb,
                int cdb_len)
{
    iscsi->cdb     = cdb;
    iscsi->cdb_len = cdb_len;
}

void
set_iscsi_pt_sense(struct sg_pt_iscsi *iscsi, unsigned char *sense,
                  int max_sense_len)
{
    memset(sense, 0, max_sense_len);
    iscsi->sense         = sense;
    iscsi->max_sense_len = max_sense_len;
}

void
set_iscsi_pt_data_in(struct sg_pt_iscsi *iscsi, unsigned char *dxferp,
                    int dxfer_len)
{
    if (dxfer_len > 0) {
        iscsi->datain.data = dxferp;
        iscsi->datain.size = dxfer_len;
        iscsi->xferdir     = SCSI_XFER_READ;
    }
}

void
set_iscsi_pt_data_out(struct sg_pt_iscsi *iscsi, const unsigned char *dxferp,
                     int dxfer_len)
{
    if (dxfer_len > 0) {
        iscsi->dataout.data = (unsigned char *)dxferp;
        iscsi->dataout.size = dxfer_len;
        iscsi->xferdir      = SCSI_XFER_WRITE;
    }
}

int
get_iscsi_pt_resid(const struct sg_pt_iscsi *iscsi)
{
    /* keep compiler happy */
    iscsi = iscsi;

    return 0;
}

int
get_iscsi_pt_status_response(const struct sg_pt_iscsi *iscsi)
{
    /* keep compiler happy */
    iscsi = iscsi;

    return 0;
}

int
get_iscsi_pt_result_category(const struct sg_pt_iscsi *iscsi)
{
    if (iscsi->os_err)
        return SCSI_PT_RESULT_OS_ERR;

    if (iscsi->device_status)
        return SCSI_PT_RESULT_SENSE;
    else
        return SCSI_PT_RESULT_GOOD;
}

int
get_iscsi_pt_os_err(const struct sg_pt_iscsi *iscsi)
{
    return iscsi->os_err;
}

int
get_iscsi_pt_sense_len(const struct sg_pt_iscsi *iscsi)
{
    return iscsi->sense_len;
}

int
iscsi_pt_close_device(int fd)
{
    struct iscsi_lun_context *iscsi = iscsi_contexts[fd & ISCSI_FAKE_FD_MASK];

    iscsi_logout_sync(iscsi->context);
    iscsi_destroy_context(iscsi->context);
    free(iscsi);
    iscsi = NULL;
    return 0;
}

char *
get_iscsi_pt_os_err_str(const struct sg_pt_iscsi *iscsi, int max_b_len, char * b)
{
    const char * cp;

    cp = safe_strerror(iscsi->os_err);
    strncpy(b, cp, max_b_len);
    if ((int)strlen(cp) >= max_b_len)
        b[max_b_len - 1] = '\0';
    return b;
}

int
get_iscsi_pt_transport_err(const struct sg_pt_iscsi *iscsi)
{
    /* keep compiler happy */
    iscsi = iscsi;

    return 0;
}

char *
get_iscsi_pt_transport_err_str(const struct sg_pt_iscsi *iscsi, int max_b_len,
                              char *b)
{
    /* keep compiler happy */
    iscsi = iscsi;
    max_b_len = max_b_len;
    b = b;

    return "";
}

int
iscsi_pt_open_device(const char *device_name, int read_only, int verbose)
{
    static int context_num = 0;
    struct iscsi_lun_context *iscsi;
    struct iscsi_url *iscsi_url = NULL;

    /* keep compiler happy */
    read_only = read_only;
    verbose = verbose;

    if (strncmp(device_name, "iscsi://", 8)) {
        return -EINVAL;
    }

    iscsi = malloc(sizeof(struct iscsi_lun_context));
    iscsi->context = iscsi_create_context("iqn.2010-12.org.sg3utils");
    if (!iscsi->context) {
        fprintf(stderr, "Failed to create iscsi context for url %s\n%s\n",
                device_name, iscsi_get_error(iscsi->context));
        free(iscsi);
        iscsi = NULL;
        return -EINVAL;
    }

    iscsi_url = iscsi_parse_full_url(iscsi->context, device_name);
    if (iscsi_url == NULL) {
        fprintf(stderr, "Failed to parse URL: %s\n", 
                iscsi_get_error(iscsi->context));
        iscsi_destroy_context(iscsi->context);
        free(iscsi);
        iscsi = NULL;
        return -EINVAL;
    }

    iscsi->lun = iscsi_url->lun;
    iscsi_set_targetname(iscsi->context, iscsi_url->target);
    iscsi_set_session_type(iscsi->context, ISCSI_SESSION_NORMAL);
    iscsi_set_header_digest(iscsi->context, ISCSI_HEADER_DIGEST_NONE_CRC32C);

    if (iscsi_url->user != NULL) {
        if (iscsi_set_initiator_username_pwd(iscsi->context, iscsi_url->user, iscsi_url->passwd) != 0) {
            fprintf(stderr, "Failed to set initiator username and password\n%s\n",
                    iscsi_get_error(iscsi->context));
            iscsi_destroy_url(iscsi_url);
            iscsi_destroy_context(iscsi->context);
            free(iscsi);
            iscsi = NULL;
            return -EINVAL;
        }
    }

    if (iscsi_full_connect_sync(iscsi->context, iscsi_url->portal, iscsi->lun) != 0) {
        fprintf(stderr, "iSCSI login failed: %s\n",
                iscsi_get_error(iscsi->context));
        iscsi_destroy_context(iscsi->context);
        free(iscsi);
        iscsi = NULL;
        return -EINVAL;
    }

    iscsi_contexts[context_num] = iscsi;

    return ISCSI_FAKE_FD_BASE + context_num++;
}

#endif
