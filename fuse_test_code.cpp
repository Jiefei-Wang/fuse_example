#define FUSE_USE_VERSION 26

#include <chrono>
#include <future>
#include <thread>
#include <string.h>
#include <memory>
#include <vector>
#include <unistd.h>
#include <sys/mman.h>
#include <fuse_lowlevel.h>
using namespace std;

//fuse filesystem thread
std::unique_ptr<std::thread> filesystem_thread(nullptr);

//fuse specific objects
static fuse_chan *channel = NULL;
static fuse_session *session = NULL;
static fuse_lowlevel_ops filesystem_operations;

//Mount point and test file path
std::string mount_point(std::string(getenv("HOME")) + "/Documents/mount_test");
std::string test_file_path(mount_point+"/"+FILE_NAME);

//The virtual file name and size
#define FILE_NAME "inode2"
#define FILE_SIZE 1024 * 1024 * 1024
#define FILE_INODE 2

//function declaration
void filesystem_thread_func();
void write_test();

int main()
{
    printf("Testing the file in: %s\n", test_file_path.c_str());
    //Run fuse filesystem in another thread
    filesystem_thread.reset(new std::thread(filesystem_thread_func));
    printf("Press any key to perform the test");
    getchar();
    //Test the fuse write function
    //It will freeze the program
    write_test();
    printf("Test finished\n");
    filesystem_thread->join();
    return 0;
}

void write_test()
{
    //Open a file handle to a virtual file in the filesystem
    int fd = open(test_file_path.c_str(), O_RDWR);
    if (fd == -1)
    {
        printf("Faile to open the file\n");
        return;
    }
    //Map the file to the current process
    //Treat the file data as integer
    int *ptr = (int *)mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == (void *)-1)
    {
        printf("Faile to map the file\n");
        close(fd);
        return;
    }
    //Write data to the file
    uint64_t n = FILE_SIZE / 4;
    uint64_t offset = 1024;
    for (uint64_t i = 0; i < offset; i++)
    {
        printf("testing offset %lu\n", i);
        for (uint64_t j = offset; j < n; j = j + offset)
        {
            ptr[j] = -j;
        }
    }
    //Unmap the file
    munmap(ptr, FILE_SIZE);
}

/*
========================================================
fuse operations, most are from
https://github.com/libfuse/libfuse/blob/fuse-2_9_bugfix/example/hello_ll.c
========================================================
*/
static int fill_file_stat(fuse_ino_t ino, struct stat *stbuf)
{
    stbuf->st_ino = ino;
    if (ino == 1)
    {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    if (ino == FILE_INODE)
    {
        stbuf->st_mode = S_IFREG | 0666;
        stbuf->st_nlink = 1;
        stbuf->st_size = FILE_SIZE;
        return 0;
    }
    return -1;
}

//Assigned
static void filesystem_getattr(fuse_req_t req, fuse_ino_t ino,
                               struct fuse_file_info *fi)
{

    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    if (fill_file_stat(ino, &stbuf) == -1)
    {
        fuse_reply_err(req, ENOENT);
    }
    else
    {
        fuse_reply_attr(req, &stbuf, 1.0);
    }
}
//Assigned
static void filesystem_loopup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    struct fuse_entry_param e;
    if (parent != FUSE_ROOT_ID || strcmp(name, FILE_NAME) != 0)
    {
        fuse_reply_err(req, ENOENT);
        return;
    }
    memset(&e, 0, sizeof(e));
    e.ino = FILE_INODE;
    e.attr_timeout = 0;
    e.entry_timeout = 0;
    fill_file_stat(e.ino, &e.attr);
    fuse_reply_entry(req, &e);
}

struct dirbuf
{
    char *p;
    uint64_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
                       fuse_ino_t ino)
{
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;

    uint64_t oldsize = b->size;
    b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    b->p = (char *)realloc(b->p, b->size);
    fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
                      b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, uint64_t bufsize,
                             off_t off, uint64_t maxsize)
{
    if ((uint64_t)off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

//Assigned
static void filesystem_readdir(fuse_req_t req, fuse_ino_t ino, uint64_t size,
                               off_t off, struct fuse_file_info *fi)
{
    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else
    {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        dirbuf_add(req, &b, ".", 1);
        dirbuf_add(req, &b, "..", 1);
        dirbuf_add(req, &b, FILE_NAME, FILE_INODE);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static void filesystem_open(fuse_req_t req, fuse_ino_t ino,
                            fuse_file_info *fi)
{

    if (ino != FILE_INODE)
    {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if ((fi->flags & O_ACCMODE) != O_RDWR &&
        (fi->flags & O_ACCMODE) != O_RDONLY)
    {
        fuse_reply_err(req, EACCES);
        return;
    }
    fi->nonseekable = false;
    fuse_reply_open(req, fi);
}

//Data buffer
std::unique_ptr<char[]> unique_buffer;
static void filesystem_read(fuse_req_t req, fuse_ino_t ino, uint64_t size,
                            off_t offset, fuse_file_info *fi)
{
    unique_buffer.reset(new char[size]);
    fuse_reply_buf(req, unique_buffer.get(), size);
    return;
}

//The problematic function. It does nothing but allocates the memory
std::vector<std::unique_ptr<char[]>> ptr_list;
static void filesystem_write(fuse_req_t req, fuse_ino_t ino, const char *buffer,
                             uint64_t buffer_length, off_t offset, struct fuse_file_info *fi)
{
    printf("Write %llu, size: %llu\n",
           (unsigned long long int)offset,
           (unsigned long long int)buffer_length);
    fuse_reply_write(req, buffer_length);
    //If you comment below out, everything is good
    ptr_list.emplace_back(new char[4096]);
    printf("Finish\n");
}

/*
========================================================
fuse main function
========================================================
*/
void filesystem_thread_func()
{
    //Create the directory if it does not exist
    mkdir(mount_point.c_str(), 0755);
    filesystem_operations.lookup = filesystem_loopup;
    filesystem_operations.getattr = filesystem_getattr;
    filesystem_operations.readdir = filesystem_readdir;
    filesystem_operations.open = filesystem_open;
    filesystem_operations.read = filesystem_read;
    filesystem_operations.write = filesystem_write;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    channel = fuse_mount(mount_point.c_str(), &args);
    if (channel != NULL)
    {
        session = fuse_lowlevel_new(&args, &filesystem_operations,
                                    sizeof(filesystem_operations), NULL);
        if (session != NULL)
        {
            fuse_session_add_chan(session, channel);
            fuse_session_loop(session);
            fuse_session_remove_chan(channel);
        }
        fuse_session_destroy(session);
    }
    fuse_opt_free_args(&args);
}


