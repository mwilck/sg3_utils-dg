/*
 * Copyright (c) 2010 Ronnie Sahlberg
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* Any FD where the top 28 bits are x7ffffff are special iscsi "descriptors"
 * where the low 4 bits reference the context number.
 * There can be up to 16 different iscsi contexts at the same time
 */ 
#define ISCSI_FAKE_FD_BASE 0x7ffffff0
#define ISCSI_FAKE_FD_MASK 0x0000000f
#define ISCSI_MAX_CONTEXTS 16

extern struct iscsi_lun_context *iscsi_contexts[ISCSI_MAX_CONTEXTS];

struct sg_pt_iscsi *construct_iscsi_pt_obj(void);
void destruct_iscsi_pt_obj(struct sg_pt_iscsi *iscsi);
int iscsi_pt_open_device(const char *device_name, int read_only, int verbose);
int iscsi_pt_close_device(int device_fd);
void set_iscsi_pt_cdb(struct sg_pt_iscsi *iscsi, const unsigned char *cdb, int cdb_len);
void set_iscsi_pt_sense(struct sg_pt_iscsi *iscsi, unsigned char *sense, int max_sense_len);
void set_iscsi_pt_data_in(struct sg_pt_iscsi *iscsi, unsigned char *dxferp, int dxfer_len);
void set_iscsi_pt_data_out(struct sg_pt_iscsi *iscsi, const unsigned char *dxferp, int dxfer_len);
void clear_iscsi_pt_obj(struct sg_pt_iscsi *iscsi);
int get_iscsi_pt_resid(const struct sg_pt_iscsi *iscsi);
int do_iscsi_pt(struct sg_pt_iscsi *iscsi, int fd, int time_secs, int verbose);
int get_iscsi_pt_result_category(const struct sg_pt_iscsi *iscsi);
int get_iscsi_pt_os_err(const struct sg_pt_iscsi *iscsi);
char *get_iscsi_pt_os_err_str(const struct sg_pt_iscsi *iscsi, int max_b_len, char *b);
int get_iscsi_pt_transport_err(const struct sg_pt_iscsi *iscsi);
char *get_iscsi_pt_transport_err_str(const struct sg_pt_iscsi *iscsi, int max_b_len, char *b);
int get_iscsi_pt_sense_len(const struct sg_pt_iscsi *iscsi);
int get_iscsi_pt_status_response(const struct sg_pt_iscsi *iscsi);
