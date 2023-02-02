#include <linux/err.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kernfs.h>
#include <linux/seq_file.h>
#include <linux/sysfs.h>
#include <linux/user_namespace.h>

#include <uapi/linux/magic.h>

struct knitfs {
    struct kernfs_node *kn;
};

static struct kernfs_root *knitfs_root;
static struct kernfs_fs_context *kfc;
struct knitfs knitfs_default;

static ssize_t points_write(struct kernfs_open_file *of, char *buf, size_t nbytes, loff_t off) {
    return -ENOTSUPP;
}

static int points_show(struct seq_file *m, void *arg) {
    seq_puts(m, "what it do\n");
    return 0;
}

static const struct kernfs_ops kfs_ops = {
    .atomic_write_len = PAGE_SIZE,
    .write = points_write,
    .seq_show = points_show,
};

static int knitfs_mkdir(struct kernfs_node *parent_kn, const char *name, umode_t mode) {
    return -ENOTSUPP;
}

static int knitfs_rmdir(struct kernfs_node *kn) {
    return -ENOTSUPP;
}

static int knitfs_show_options(struct seq_file *seq, struct kernfs_root *kf) {
    seq_puts(seq, ",tracing");
    return 0;
}


static struct kernfs_syscall_ops knitfs_syscall_ops = {
    .mkdir = knitfs_mkdir,
    .rmdir = knitfs_rmdir,
    .show_options = knitfs_show_options,
};

static int knit_get_tree(struct fs_context *fc) {
    int ret;
    ret = kernfs_get_tree(fc);
    return ret;
}

static int knit_parse_param(struct fs_context *fc, struct fs_parameter *param) {
    return 0;
}

static void knit_fs_context_free(struct fs_context *fc) {
    kernfs_free_fs_context(fc);
}

static const struct fs_context_operations knit_fs_context_ops = {
    .free = knit_fs_context_free,
    .parse_param = knit_parse_param,
    .get_tree = knit_get_tree,
};

static int knit_init_fs_context(struct fs_context *fc) {
    kfc = kzalloc(sizeof(struct kernfs_fs_context), GFP_KERNEL);
    if (!kfc)
        return -ENOMEM;

    kfc->root = knitfs_root;
    kfc->magic = TRACEFS_SUPER_MAGIC;
    fc->fs_private = kfc;
    fc->ops = &knit_fs_context_ops;
    put_user_ns(fc->user_ns);
    fc->user_ns = get_user_ns(&init_user_ns);
    fc->global = true;
    return 0;
}

static void knit_kill_sb(struct super_block *sb) {
    kernfs_kill_sb(sb);
}

static struct file_system_type knit_fs_type = {
    .name = "knitfs",
    .init_fs_context = knit_init_fs_context,
    .kill_sb = knit_kill_sb,
};

static int set_ugid(struct kernfs_node *kn) {
    struct iattr iattr = {
	.ia_valid = ATTR_UID | ATTR_GID,
	.ia_uid = current_fsuid(),
        .ia_gid = current_fsgid(),
    };

    if (uid_eq(iattr.ia_uid, GLOBAL_ROOT_UID) &&
        gid_eq(iattr.ia_gid, GLOBAL_ROOT_GID))
        return 0;
    
    return kernfs_setattr(kn, &iattr);
}

int __init knit_init(void) {
    struct kernfs_node *kn;
    int ret; 

    knitfs_root = kernfs_create_root(
        &knitfs_syscall_ops,
        KERNFS_ROOT_CREATE_DEACTIVATED | KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK,
        &knitfs_default
    );
    if (IS_ERR(knitfs_root))
        return PTR_ERR(knitfs_root);

    kn = __kernfs_create_file(
        knitfs_root->kn,
        "points",
        0644,
        GLOBAL_ROOT_UID,
        GLOBAL_ROOT_GID,
        0,
        &kfs_ops,
        NULL,
        NULL,
        NULL
    );
    if (IS_ERR(kn))
        return PTR_ERR(kn);

    set_ugid(kn);

    kernfs_activate(knitfs_root->kn);

    ret = sysfs_create_mount_point(fs_kobj, "knit");
    if (ret) {
        sysfs_remove_mount_point(fs_kobj, "knit");
        return ret;
    }

    ret = register_filesystem(&knit_fs_type);
    if (ret) {
        kernfs_destroy_root(knitfs_root);
        return ret;
    }

    return 0;
}

late_initcall(knit_init);
