#include <stdio.h>
#include <stdlib.h>
#include <udis86.h>

#ifndef _WP_STRUCT_
#define _WP_STRUCT_
typedef struct _CODE_INFORMATION_
{
	unsigned char * buf; //���뻺����
	unsigned long  size; //��С
	unsigned long base; // ��ַ
}CodeInformation,*pCodeInformation;

typedef struct _INSTRUCTION_LIST_
{
	int id;
	ud_t udobj;
	_INSTRUCTION_LIST_ *next;
}InstructionList,*pInstructionList;

typedef struct _INSTRUCTION_BLOCK_LIST_
{
	int id;
	pInstructionList list;	
	unsigned long oldaddr;
	unsigned long newaddr;
	_INSTRUCTION_BLOCK_LIST_ *next;
}InstructionBlockList,*pInstructionBlockList;
#endif