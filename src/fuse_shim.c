#define _GNU_SOURCE 1
#define FUSE_USE_VERSION 318
#include "fuse_shim.h"

void permbox_conn_set_backing_depth(struct fuse_conn_info *conn, uint32_t depth) {
    conn->max_backing_stack_depth = depth;
}

int permbox_fi_flags(const struct fuse_file_info *fi) { return fi->flags; }
uint64_t permbox_fi_fh(const struct fuse_file_info *fi) { return fi->fh; }
void permbox_fi_set_fh(struct fuse_file_info *fi, uint64_t fh) { fi->fh = fh; }
void permbox_fi_set_backing_id(struct fuse_file_info *fi, int32_t id) {
    fi->backing_id = id;
}
int32_t permbox_fi_backing_id(const struct fuse_file_info *fi) {
    return fi->backing_id;
}
void permbox_fi_set_keep_cache(struct fuse_file_info *fi, unsigned value) {
    fi->keep_cache = value;
}
void permbox_fi_set_noflush(struct fuse_file_info *fi, unsigned value) {
    fi->noflush = value;
}
void permbox_fi_set_cache_readdir(struct fuse_file_info *fi, unsigned value) {
    fi->cache_readdir = value;
}
