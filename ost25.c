/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  This program can be distributed under the terms of the GNU GPL.
*/

#define FUSE_USE_VERSION 26
#define MAX_FILE_NAME 100

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>

typedef struct dir {
	char *name;
	char *data;
	struct dir *parent;
	struct dir *next;
	struct dir *child;
	struct stat md;
} dir_t;

dir_t root;
struct stat r_stat;

// Insert child node to parent node
int insert_dir(dir_t *p, dir_t *c) {
	dir_t *prev = p->child;
	c->parent = p;

	if (prev == NULL) {
		p->child = c;
		c->next = NULL;
	}
	else {
		while (prev->next != NULL) {
			prev = prev->next;
		}
		prev->next = c;
		c->next = NULL;
	}
	
	if (c->md.st_mode & S_IFDIR)
		p->md.st_nlink++;

	return 1;
}

// Remove child node from parent node
int remove_dir(dir_t *c) {
	dir_t *p = c->parent;
	if (p == NULL)
		return -EROFS;
	if (c->child != NULL)
		return -ENOTEMPTY;
	
	dir_t *prev = p->child;
	if (prev == c) {
		p->child = c->next;
	}
	else {
		while (prev->next != c)
			prev = prev->next;
		prev->next = c->next;
	}
	if (c->md.st_mode & S_IFDIR)
		p->md.st_nlink--;
	if (c->name != NULL)
		free(c->name);
	if (c->data != NULL)
		free(c->data);
	free(c);
	return 0;
}

// Search dir from path
int search_dir(const char *path, dir_t **buf) {
	dir_t *current = &root;
	*buf = current;
	char *name_t;
	char *path_t = (char *)calloc(strlen(path) + 1, sizeof(char));
	memcpy(path_t, path, strlen(path) + 1);
	char *save = path_t;
	
	name_t = strtok(path_t, "/");
	dir_t *child_t;
	while (name_t != NULL) {
		int flag = 0;
		child_t = current->child;
		while (child_t != NULL) {
			if (strcmp(child_t->name, name_t) == 0) {
				current = child_t;
				flag = 1;
				break;
			}
			child_t = child_t->next;
		}
		name_t = strtok(NULL, "/");
		if (flag) 
			continue;
		
		free(save);
		return -ENOENT;
	}

	free(save);
	*buf = current;
	return 0;
}

int check_permission(dir_t *entry) {
	int permission = 0;
	int gidsize;
	gid_t *groups;
	struct fuse_context *context = fuse_get_context();
	if (context->uid == entry->md.st_uid)
		permission = permission | ((entry->md.st_mode & 0700) >> 6);
	gidsize = getgroups(0, NULL);
	if ((groups = (gid_t*)malloc(gidsize * sizeof(gid_t))) == NULL)
		return -ENOMEM;
	getgroups(gidsize, groups);
	for (int i = 0; i < gidsize; ++i) {
		if (groups[i] == entry->md.st_gid) {
			permission = permission | ((entry->md.st_mode & 070) >> 3);
			break;
		}
	}
	permission = permission | (entry->md.st_mode & 07);
	if (context->uid == 0)
		permission = 7;
	return permission;
}

static void *ost25_init(struct fuse_conn_info *conn) {
	(void) conn;
	memset(&root, 0, sizeof(dir_t));
	time_t ct = time(NULL);
	r_stat.st_nlink = 2;
	r_stat.st_mode = S_IFDIR | 0755;
	r_stat.st_uid = getuid();
	r_stat.st_gid = getgid();
	r_stat.st_atime = ct;
	r_stat.st_mtime = ct;
	r_stat.st_ctime = ct;
	r_stat.st_size = 0;
	root.md = r_stat;
	return NULL;
}

static int ost25_access(const char *path, int mask) {
	dir_t *current;

	if (search_dir(path, &current) != 0)
		return -ENOENT;

	if ((mask & 01) == 0)
		return -EACCES;

	int permission = check_permission(current);
	if ((permission & 01) == 0)
		return -EACCES;
	
	return 0;
}

static int ost25_getattr(const char *path, struct stat *stbuf)
{	
	dir_t *current;

	if (search_dir(path, &current) != 0)
		return -ENOENT;

	memcpy(stbuf, &(current->md), sizeof(struct stat));

	return 0;	
}

static int ost25_opendir(const char *path, struct fuse_file_info *fi) {
	dir_t *current;

	if (fi != NULL && (dir_t*)fi->fh != NULL) {
		current = (dir_t *)fi->fh;
	}
	else {
		if (search_dir(path, &current) != 0){
			return -ENOENT;
		}
	}
	
	int permission = check_permission(current);
	if ((permission & 04) == 0)
		return -EACCES;

	return 0;
}

static int ost25_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	dir_t *current;
	dir_t *child_t;

	if (fi != NULL && (dir_t*)fi->fh != NULL) {
		current = (dir_t *)fi->fh;
	}
	else {
		if (search_dir(path, &current) != 0){
			return -ENOENT;
		}
	}

	int permission = check_permission(current);
	if ((permission & 04) == 0)
		return -EACCES;

	filler(buf, ".", &current->md, 0);
	if (current->parent != NULL)
		filler(buf, "..", &current->parent->md, 0);
	else
		filler(buf, "..", NULL, 0);

	child_t = current->child;
	while (child_t != NULL) {
		filler(buf, child_t->name, &child_t->md, 0);
		child_t = child_t->next;
	}

	return 0;
}

static int ost25_open(const char *path, struct fuse_file_info *fi)
{
	dir_t *current;
	if (search_dir(path, &current) != 0)
		return -ENOENT;
	fi->fh = (uint64_t)current;

	int permission = check_permission(current);
	
	int flag = fi->flags & 3;
	if (flag == O_RDONLY && (permission & 04) == 0)
		return -EACCES;
	else if (flag == O_WRONLY && (permission & 02) == 0)
		return -EACCES;
	else if (flag == O_RDWR && (permission & 06) == 0)
		return -EACCES;

	current->md.st_atime = time(NULL);
	return 0;
}

static int ost25_truncate(const char *path, off_t size) 
{
	dir_t *current;

	if (search_dir(path, &current) != 0)
		return -ENOENT;
	if (current->md.st_mode & S_IFDIR)
		return -EISDIR;

	if (size == 0) {
		free(current->data);
		current->data = NULL;
		current->md.st_size = 0;
	}
	else {
		if (realloc(current->data, size * sizeof(char)) == NULL)
			return -ENOMEM;
		current->md.st_size = size;
	}

	current->md.st_mtime = time(NULL);
	return size;
}

static int ost25_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	off_t filesize;
	dir_t *current;

	if (fi != NULL && (dir_t*)fi->fh != NULL) {
		current = (dir_t *)fi->fh;
		if ((fi->flags & O_WRONLY) == O_WRONLY)
			return -EACCES;
	}
	else {
		if (search_dir(path, &current) != 0){
			return -ENOENT;
		}
	}
	if (current->md.st_mode & S_IFDIR)
		return -EISDIR;
	

	filesize = current->md.st_size;
	if (current->data == NULL)
		return 0;
	if (offset < filesize) {
		if (filesize - offset < size)
			size = filesize - offset;
		memcpy(buf, current->data + offset, size);
	} else
		size = 0;

	return size;
}

static int ost25_write(const char *path, const char *buf, size_t size, off_t offset, 
		      struct fuse_file_info *fi) 
{
	dir_t *current;

	if (fi != NULL && (dir_t*)fi->fh != NULL) {
		current = (dir_t *)fi->fh;
	}
	else {
		if (search_dir(path, &current) != 0){
			return -ENOENT;
		}
	}
	if (current->md.st_mode & S_IFDIR)
		return -EISDIR;

	if (current->data == NULL) {
		current->data = (char*)calloc(offset + size , sizeof(char));
		if (current->data == NULL)
			return -ENOMEM;
		current->md.st_size = offset + size;
	} else if (current->md.st_size < offset + size) {
		if (realloc(current->data, (offset + size) * sizeof(char)) == NULL)
			return -ENOMEM;
		current->md.st_size = offset + size;
	}
	memcpy(current->data + offset, buf, size);
	current->md.st_mtime = time(NULL);
	return size;
}

static int ost25_mknod(const char *path, mode_t mode, dev_t rdev) {
	dir_t *p;
	char *last = strrchr(path, '/');
	char *path_p = (char *)calloc(last - path + 2, sizeof(char));
	memcpy(path_p, path, last - path + 1);
	path_p[last - path + 1] = '\0';

	if (search_dir(path_p, &p) != 0){
		free(path_p);
		return -ENOENT;
	}
	free(path_p);

	int permission = check_permission(p);
	if ((permission & 02) == 0)
		return -EACCES;
	
	struct fuse_context *context = fuse_get_context();
	time_t now = time(NULL);
	dir_t *node = (dir_t *)calloc(1, sizeof(dir_t));
	if (node == NULL)
		return -ENOMEM;
	node->md.st_mode = mode;
	node->name = (char *)calloc(strlen(last + 1) + 1, sizeof(char));
	memcpy(node->name, last + 1, strlen(last + 1) + 1);
	node->md.st_nlink = 1;
	node->md.st_rdev = rdev;
	node->md.st_uid = context->uid;
	node->md.st_gid = context->gid;
	node->md.st_atime = now;
	node->md.st_mtime = now;
	node->md.st_ctime = now;
	node->md.st_size = 0;
	if (insert_dir(p, node) == 0)
		return -ENOMEM;	

	return 0;
}

static int ost25_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	dir_t *p;
	char *last = strrchr(path, '/');
	char *path_p = (char *)calloc(last - path + 2, sizeof(char));
	memcpy(path_p, path, last - path + 1);
	path_p[last - path + 1] = '\0';

	if (search_dir(path_p, &p) != 0){
		free(path_p);
		return -ENOENT;
	}

	free(path_p);
	int permission = check_permission(p);
	if ((permission & 02) == 0)
		return -EACCES;
	
	struct fuse_context *context = fuse_get_context();
	time_t now = time(NULL);
	dir_t *node = (dir_t *)calloc(1, sizeof(dir_t));
	if (node == NULL)
		return -ENOMEM;
	node->md.st_mode = mode;
	node->name = (char *)calloc(strlen(last + 1) + 1, sizeof(char));
	memcpy(node->name, last + 1, strlen(last + 1) + 1);
	node->md.st_nlink = 1;
	node->md.st_uid = context->uid;
	node->md.st_gid = context->gid;
	node->md.st_atime = now;
	node->md.st_mtime = now;
	node->md.st_ctime = now;
	node->md.st_size = 0;
	if (insert_dir(p, node) == 0)
		return -ENOMEM;	

	fi->fh = (uint64_t)node;

	return 0;
}

static int ost25_mkdir(const char *path, mode_t mode){
	dir_t *p;
	char *last = strrchr(path, '/');
	char *path_p = (char *)calloc(last - path + 2, sizeof(char));
	memcpy(path_p, path, last - path + 1);
	path_p[last - path + 1] = '\0';

	if (search_dir(path_p, &p) != 0) {
		free(path_p);
		return -ENOENT;
	}

	free(path_p);
	int permission = check_permission(p);
	if ((permission & 02) == 0)
		return -EACCES;
	
	struct fuse_context *context = fuse_get_context();
	time_t now = time(NULL);
	dir_t *node = (dir_t *)calloc(1, sizeof(dir_t));
	if (node == NULL)
		return -ENOMEM;
	node->md.st_mode = mode | S_IFDIR;
	node->name = (char *)calloc(strlen(last + 1) + 1, sizeof(char));
	memcpy(node->name, last + 1, strlen(last + 1) + 1);
	node->md.st_nlink = 2;
	node->md.st_uid = context->uid;
	node->md.st_gid = context->gid;
	node->md.st_atime = now;
	node->md.st_mtime = now;
	node->md.st_ctime = now;
	node->md.st_size = 0;
	if (insert_dir(p, node) == 0)
		return -ENOMEM;	
	return 0;
}

static int ost25_unlink(const char *path) {
	dir_t *current;

	if (search_dir(path, &current) != 0)
		return -ENOENT;
	if (current->md.st_mode & S_IFDIR)
		return -EISDIR;

	return remove_dir(current);
}

static int ost25_rmdir(const char *path) {
	dir_t *current;

	if (search_dir(path, &current) != 0)
		return -ENOENT;
	if ((current->md.st_mode & S_IFDIR) == 0)
		return -ENOTDIR;

	return remove_dir(current);
}

static int ost25_rename(const char *oldpath, const char *newpath) {
	dir_t *current;
	if (strcmp(oldpath, newpath) == 0)
		return 0;

	if (search_dir(oldpath, &current) != 0)
		return -ENOENT;
	
	if (current == &root) 
		return -EROFS;

	int permission = check_permission(current);
	if ((permission & 02) == 0)
		return -EACCES;

	// Search new path
	dir_t *p;
	char *newname = strrchr(newpath, '/');
	char *path_p = (char *)calloc(newname - newpath + 2, sizeof(char));
	memcpy(path_p, newpath, newname - newpath + 1);
	path_p[newname - newpath + 1] = '\0';
	
	if (search_dir(path_p, &p) != 0) {
		free(path_p);
		return -ENOENT;
	}
	free(path_p);
	permission = check_permission(p);
	if ((permission & 02) == 0)
		return -EACCES;
	
		
	// Check duplicated name
	char *oldname = current->name;
	dir_t *child_t = p->child;
	while (child_t != NULL) {
		if (strcmp(child_t->name, newname + 1) == 0) {
			remove_dir(child_t);
			break;
		}
		child_t = child_t->next;
	}

	if (sizeof(current->name) != strlen(newname + 1) + 1) {
		if (realloc(current->name, strlen(newname + 1) + 1) == NULL)
			return -ENOMEM;
	}

	dir_t *cur_p = current->parent;
	dir_t *prev = cur_p->child;
	if (prev == current) {
		cur_p->child = current->next;
	}
	else {
		while (prev->next != current)
			prev = prev->next;
		prev->next = current->next;
	}
	if (current->md.st_mode & S_IFDIR)
		p->md.st_nlink--;

	memcpy(current->name, newname + 1, strlen(newname + 1) + 1);
	insert_dir(p, current);
	return 0;
}

static int ost25_chmod(const char* path, mode_t mode)
{
	dir_t* current;
	// if there is no path,
	if (search_dir(path, &current) != 0) {
		return -ENOENT;
	}

	// if user is not root or owner,
	struct fuse_context *context = fuse_get_context();
	if (context->uid != 0 && context->uid != current->md.st_uid)
		return -EACCES;

	current->md.st_mode = mode;
	current->md.st_ctime = time(NULL);
	return 0;
}

static int ost25_chown(const char *path, uid_t uid, gid_t gid)
{
	struct fuse_context *context = fuse_get_context();
	if (context->uid != 0) {
		return -EACCES;
	}

	dir_t* current;
	if (search_dir(path, &current) != 0) {
		return -ENOENT;
	}

	current->md.st_uid = uid;
	current->md.st_gid = gid;

	return 0;
}

static int ost25_flush(const char *path, struct fuse_file_info *fi) {
	fi->flush = 1;
	return 0;
}

static int ost25_release(const char *path, struct fuse_file_info *fi) {
	fi->fh = 0;
	return 0;
}

static struct fuse_operations ost25_oper = {
	.init		= ost25_init,
	.access		= ost25_access,
	.getattr	= ost25_getattr,
	.readdir	= ost25_readdir,
	.open		= ost25_open,
	.truncate	= ost25_truncate,
	.read		= ost25_read,
	.write		= ost25_write,
	.mknod		= ost25_mknod,
	.create		= ost25_create,
	.opendir	= ost25_opendir,
	.mkdir		= ost25_mkdir,
	.unlink		= ost25_unlink,
	.rmdir		= ost25_rmdir,
	.rename		= ost25_rename,
	.chmod		= ost25_chmod,
	.chown		= ost25_chown,
	.flush		= ost25_flush,
	.release	= ost25_release,
};

int main(int argc, char *argv[])
{
	return fuse_main(argc, argv, &ost25_oper, NULL);
}
