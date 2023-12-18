/* This file contains some types that are referenced in the function
   summaries. This file is loaded automatically for the analysis.
*/


struct _IO_FILE;
typedef struct _IO_FILE FILE;

struct _IO_DIR;
typedef struct _IO_DIR DIR;

struct _timeval;
typedef struct _timeval timeval;

void (*signal(int sig, void (*func)(int)))(int);

typedef unsigned int pthread_t;
typedef unsigned int pthread_attr_t;

int pthread_create(pthread_t *restrict thread,
       const pthread_attr_t *restrict attr,
       void *(*start_routine)(void*), void *restrict arg);

typedef unsigned long pid_t;
typedef long time_t;

typedef unsigned long size_t;
typedef long ssize_t;

typedef unsigned int sa_family_t;

struct _sockaddr {
  sa_family_t     sa_family;      /* Address family */
  char            sa_data[];      /* Socket address */
};

typedef struct _sockaddr sockaddr;

struct stat;
typedef struct stat _stat;
