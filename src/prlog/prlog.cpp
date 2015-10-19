#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include "prlog.h"

void printf_memory_data(FILE *stream, void *data, unsigned int size)
{
	char c_string[0x20];
	unsigned char c;
	int i, j;

	for (i=0; i<((int)(size/16)+(int)(size%16?1:0)); i++) {
		memset(c_string, 0, 0x20);
		fprintf(stream, "0X%08X ", (char *)data+(i*16));

		for (j=0; j<16; j++) {
			if (j < (int)(((int)((size/16)+(int)(size%16?1:0))-1)==\
						i?(size%16):16)) {
				c = *((unsigned char *)data + (i*16)+j);
				fprintf(stream, " %02X", c);

				if ((c>32) && (c<127))
					c_string[j] = c;
				else
					c_string[j] = 0x2e;
			} else {
				fprintf(stream, "   "); //3
			}
		}
		fprintf(stream, " %s\n", c_string);
	}
}

FILE *prlog_stream = NULL;

void fopenlog(const char *log) {
	prlog_stream = fopen(log, "w");
	if (prlog_stream < 0) {
		fprintf(stderr, "prlog open %s file error\n", log);
		prlog_stream = NULL;
	}
}

void fprdata(void *data, unsigned int size) {
	time_t t;
	char logfile[255];

	if (prlog_stream == NULL) {
		time(&t);
		strftime(logfile, sizeof(logfile), "%Y%m%d%H%M%S.txt", localtime(&t));
		fopenlog(logfile);
	}
	printf_memory_data(prlog_stream, data, size);
	fflush(prlog_stream);
}

void prdata(void *data, unsigned int size) {
	printf_memory_data(stdout, data, size);
}

void fprlog(const char *fmt, ...) {
    char str[100];
    unsigned int len, i, index;
    int iTemp;
    char *strTemp;
    va_list args;

    va_start(args, fmt);
    len = strlen(fmt);
    for (i=0, index=0; i<len; i++) {
        if (fmt[i] != '%') {
            str[index++] = fmt[i];
        } else {
            switch(fmt[i+1]) {
            case 'd':
            case 'D':
                iTemp = va_arg(args, int);
                strTemp = itoa(iTemp, str+index, 10);
                index += strlen(strTemp);
                i++;
                break;
			case 'x':
            case 'X':
                iTemp = va_arg(args, long);
                strTemp = itoa(iTemp, str+index, 16);
                index += strlen(strTemp);
                i++;
                break;
            case 's':
            case 'S':
                strTemp = va_arg(args, char*);
                strcpy(str + index, strTemp);
                index += strlen(strTemp);
                i++;
                break;
            default:
                str[index++] = fmt[i];
            }
        }
    }
    str[index] = '\0';
    va_end(args);

	fprintf(prlog_stream, "============================================================\n");
    fprintf(prlog_stream, "%s", str);
	fflush(prlog_stream);
}

void prlog(const char *fmt, ...) {
	char str[100];
    unsigned int len, i, index;
    int iTemp;
    char *strTemp;
    va_list args;

    va_start(args, fmt);
    len = strlen(fmt);
    for (i=0, index=0; i<len; i++) {
        if (fmt[i] != '%') {
            str[index++] = fmt[i];
        } else {
            switch(fmt[i+1]) {
            case 'd':
            case 'D':
                iTemp = va_arg(args, int);
                strTemp = itoa(iTemp, str+index, 10);
                index += strlen(strTemp);
                i++;
                break;
			case 'x':
            case 'X':
                iTemp = va_arg(args, long);
                strTemp = itoa(iTemp, str+index, 16);
                index += strlen(strTemp);
                i++;
                break;
            case 's':
            case 'S':
                strTemp = va_arg(args, char*);
                strcpy(str + index, strTemp);
                index += strlen(strTemp);
                i++;
                break;
            default:
                str[index++] = fmt[i];
            }
        }
    }
    str[index] = '\0';
    va_end(args);

	fprintf(stdout, "============================================================\n");
    fprintf(stdout, "%s", str);
}
