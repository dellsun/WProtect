#ifndef _DEBUG_H
#define _DEBUG_H
#if defined(__LINUX__)
#elif defined(__WINDOWS__)
#endif

extern void fopenlog(const char *log);
extern void fprdata(void *data, unsigned int size);
extern void prdata(void *data, unsigned int size);
extern void fprlog(const char *format, ...);
extern void prlog(const char *format, ...);

#endif
