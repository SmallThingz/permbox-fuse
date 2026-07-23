#pragma once

#include <fuse_lowlevel.h>

void permbox_conn_set_backing_depth(struct fuse_conn_info *conn, uint32_t depth);
int permbox_fi_flags(const struct fuse_file_info *fi);
uint64_t permbox_fi_fh(const struct fuse_file_info *fi);
void permbox_fi_set_fh(struct fuse_file_info *fi, uint64_t fh);
void permbox_fi_set_backing_id(struct fuse_file_info *fi, int32_t backing_id);
int32_t permbox_fi_backing_id(const struct fuse_file_info *fi);
void permbox_fi_set_keep_cache(struct fuse_file_info *fi, unsigned value);
void permbox_fi_set_noflush(struct fuse_file_info *fi, unsigned value);
void permbox_fi_set_cache_readdir(struct fuse_file_info *fi, unsigned value);
