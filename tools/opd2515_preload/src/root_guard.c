#define _GNU_SOURCE

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/*
 * This library is deliberately separate from the OPD2515 preloader.  It does
 * not perform credential changes or kernel I/O.  Once the preloader has
 * changed the current thread's uid, its first fork is a narrow, observable
 * handoff point.  We use that point to freeze the OPPO anti-root processes
 * before their reboot timer can fire; the stopped state is volatile and ends
 * with the next reboot.
 */

typedef pid_t (*fork_fn)(void);

static fork_fn real_fork;
static __thread int in_guard;

static int read_comm(pid_t pid, char *buf, size_t size) {
  char path[64];
  int n = snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
  if (n <= 0 || (size_t)n >= sizeof(path)) return 0;
  int fd = (int)syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
  if (fd < 0) return 0;
  ssize_t got = syscall(SYS_read, fd, buf, size - 1);
  syscall(SYS_close, fd);
  if (got <= 0) return 0;
  buf[got] = '\0';
  while (got > 0 && (buf[got - 1] == '\n' || buf[got - 1] == '\r')) {
    buf[--got] = '\0';
  }
  return 1;
}

static void freeze_named(const char *wanted) {
  DIR *dir = opendir("/proc");
  if (!dir) return;
  struct dirent *entry;
  while ((entry = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(entry->d_name, &end, 10);
    if (end == entry->d_name || *end != '\0' || pid_long <= 1 ||
        pid_long > (1 << 22)) {
      continue;
    }
    char comm[128];
    if (!read_comm((pid_t)pid_long, comm, sizeof(comm))) continue;
    if (strcmp(comm, wanted) == 0) {
      (void)syscall(SYS_kill, (pid_t)pid_long, SIGSTOP);
    }
  }
  closedir(dir);
}

static void freeze_guards(void) {
  /* The package's process name is exposed as `exsystemservice` in /proc/comm. */
  freeze_named("exsystemservice");
  freeze_named("com.oplus.exsystemservice");
  freeze_named("oplus_kevent");
}

__attribute__((constructor)) static void root_guard_init(void) {
  real_fork = (fork_fn)dlsym(RTLD_NEXT, "fork");
}

pid_t fork(void) {
  if (!real_fork) real_fork = (fork_fn)dlsym(RTLD_NEXT, "fork");
  if (!in_guard && syscall(SYS_getuid) == 0) {
    in_guard = 1;
    freeze_guards();
    in_guard = 0;
  }
  if (real_fork) return real_fork();
  errno = ENOSYS;
  return (pid_t)-1;
}
