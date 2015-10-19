#include "WProtectConfig.h"
#include "build_address.hpp"
#include <string.h>
#include <prlog/prlog.h>
#include <Protect/VirtualMachine/VirtualMachineManage.hpp>
#include <Protect/VirtualMachine/VMAddressTable.hpp>
#include <Protect/VirtualMachine/BuildVMByteCode.hpp>
#include <Analysis/Analysis.hpp>
#include <PE/PESection.h>
#include <PE/PEReloc.h>
#include <ELF/ELFFile.h>

void get_wprotect_sdk_address(CPESection & section,
	BuildCodeInfo & build_info, char *sz_sdk_begin_name,
	char *sz_sdk_end_name) {
	int sdk_begin_count = 0;
	int sdk_end_count = 0;
	int protect_begin_address = 0;
	int protect_end_address = 0;
	int section_count = section.GetSectionCount();

	fprlog("\nsection count: %d", section_count);
	for (int index = 0;index <  section_count;index++) {
		DWORD section_size;
		BYTE * ptr_section_data = section.GetSectionData(index,&section_size);
		if (ptr_section_data == NULL)
			continue;

		fprlog("\nindex: [%d] section data len: [0x%x]\n", index, section_size);
		fprdata(ptr_section_data, section_size);

		for (int offset = 0; offset < section_size; offset ++) {
			if (ptr_section_data[offset] == 0xeb &&
				sdk_begin_count == 0 &&
				sdk_end_count == 0 &&
				offset + max(strlen(sz_sdk_begin_name)+1,strlen(sz_sdk_end_name)+1) < section_size) {
				sdk_begin_count++;
				sdk_end_count++;
				if (ptr_section_data[offset + sdk_begin_count] == strlen(sz_sdk_begin_name) + 1 &&
					sdk_begin_count == 1) {
					//定位到sz_sdk_begin_name
					sdk_begin_count++;
					sdk_end_count = 0;
					continue;
				} else {
					sdk_begin_count = 0;
				}
				if (ptr_section_data[offset + sdk_end_count] == strlen(sz_sdk_end_name) + 1
					&& sdk_end_count == 1) {
					//定位到sz_sdk_end_name
					sdk_end_count++;
					continue;
				}
				else
				{
					sdk_end_count = 0;
				}
			}
			if (sdk_begin_count > 1) {
				if (ptr_section_data[offset + 1] == sz_sdk_begin_name[sdk_begin_count-2]) {
					//计算sdk_begin_count
					sdk_begin_count++;
				}
				else {
					sdk_begin_count = 0;
					offset--;
					continue;
				}
			}
			if (sdk_end_count > 1) {
				if (ptr_section_data[offset + 1] == sz_sdk_end_name[sdk_end_count-2]) {
					//计算sdk_end_count
					sdk_end_count++;
				} else {
					sdk_end_count = 0;
					offset--;
					continue;
				}
			}
			if (sdk_begin_count == strlen(sz_sdk_begin_name) + 3) {
				//抹去sz_sdk_begin_name字样
				int sdk_begin_str_size = strlen(sz_sdk_begin_name) + 1;

				protect_begin_address = section.GetSectionVa(index,offset - sdk_begin_str_size);
				memset((void*)section.GetSectionPtr(index,offset - sdk_begin_str_size),0x90,sdk_begin_count);
				sdk_begin_count = 0;
			}
			if (sdk_end_count == strlen(sz_sdk_end_name) + 3) {
				//抹去sz_sdk_end_name字样
				int sdk_end_str_size = strlen(sz_sdk_end_name) + 1;
				protect_end_address = section.GetSectionVa(index,offset - sdk_end_str_size);
				if (protect_begin_address == 0 ) {
				} else {
					build_piece piece;
					piece.build_exec_addr = protect_begin_address;
					piece.build_exec_size = protect_end_address - protect_begin_address + sdk_end_str_size + 2;
					build_info.push_back(piece);

					fprlog("\nprotect address: [0x%x] size: [0x%x]\n", piece.build_exec_addr, piece.build_exec_size);
				}
				protect_begin_address = 0;
				protect_end_address = 0;
				memset((void*)section.GetSectionPtr(index,offset - sdk_end_str_size),0x90,sdk_end_count);
				sdk_end_count = 0;
			}
		}
   }
}


void get_table_addr(CPESection &section, std::vector<long> & addr_table_entry,std::vector<long *> & addr_table_entry_point)
{
    for (std::vector<long>::iterator iter = addr_table_entry.begin();
         iter != addr_table_entry.end();iter++)
    {
        if (section.CheckAddressValidity(*iter))
        {
            long *addr = (long*)section.VaToPtr(*iter);
            //printf("table addr:%08x\r\n",*addr);
            if (addr)
            while (section.CheckAddressValidity(*addr))
            {
#ifdef DEBUG
                printf ("table addr:%08x\n",*addr);
#endif
                addr_table_entry_point.push_back(addr);
                addr++;

            }
            //addr++;
        }
    }
}


void add_jmp_addr(CPEFile pe,long base,long jmp_address)
{
  char * c = (char*)pe.VaToPtr(base);
  *(char*)c = 0xe9;
  *(long*)(c + 1) = jmp_address - base - 5;
}

void add_jmp_addr_elf(CELFFile file,long base,long jmp_address)
{
   char * c = (char*)file.VaToPtr(base);
  *(char*)c = 0xe9;
  *(long*)(c + 1) = jmp_address - base - 5;
}

void buildvmtest(BuildCodeInfo & build_info) {
	VirtualMachineManage vm;
	CodeBufferInfo info;
	CPEFile file;

	char * build_exec_name = build_info.get_filename();
	bool b = file.LoadPEFile(build_exec_name);
	if (!b) {
		printf("file is not find\r\n");
		return;
	}

	CPESection section;
	CPEReloc reloc;
	section = file;
	reloc = file;
	reloc.DeleteReloc();
	reloc.GetBaseReloc();

	//获取要加密数据段
	get_wprotect_sdk_address(section, build_info, "WProtect Begin", "WProtect End");

	//添加新节点
	VMAddressTable table(section.GetNewSectionBase(), 0x512, false);

	//获取虚拟地址
	bool t_sign = table.get_sign();
	table.set_sign(true);
	long virtualmachine_address = table.assign_address(0x1024);
	table.set_sign(t_sign);

	//添加VM
	VirtualMachine *pvm = vm.add_virtual_machine(virtualmachine_address,false);

	//
	table.copy(virtualmachine_address, pvm->vm_info.buf, pvm->vm_info.size);

	fprlog("\nvirtualmachine size: [%x]\n", pvm->vm_info.size);
	fprdata(pvm->vm_info.buf, pvm->vm_info.size);

	for (BuildCodeInfo::iterator iter = build_info.begin(); iter != build_info.end(); iter++) {
		long build_exec_addr = iter->build_exec_addr;
		long build_exec_size = iter->build_exec_size;
		info.buf = file.VaToPtr(build_exec_addr);
		info.addr = build_exec_addr;
		//info.size = 0x40194f - 0x4014a0;
		info.size = build_exec_size;
		if (info.size < 5) {
			return;
		}

		void * ptr_old_code = info.buf;
		size_t old_code_size = info.size;

		Analysis analysis;
		std::vector<long> addr_table;
		std::vector<long*> addr_entry_point;
		analysis.analysis_address_table(&info, addr_table,
			section.GetSectionMinAddress(), section.GetSectionMaxAddress());
		get_table_addr(section, addr_table, addr_entry_point);

		BuildVMByteCode build(&vm, &info, &table, addr_entry_point);
		memset(ptr_old_code, 0, old_code_size);
		add_jmp_addr(file, build_exec_addr, info.addr);
	}

	unsigned long section_size;
	section_size = (unsigned long)( table.buffer_size);
	section.AddSection(".WProtect",section_size,0xE0000020);
	section.WriteSectionData(file.GetSectionCount()-1,0,
		(unsigned char*)table.buffer,(unsigned long *)&table.buffer_size);

	fprlog("\nwrite section data\n");
	fprdata(table.buffer, table.buffer_size);

	char new_file_name[256];
	memset(new_file_name,0,256);
	memcpy(new_file_name,build_exec_name,strlen(build_exec_name)-3);
	strcat(new_file_name,"wp.exe");
	file.SavePEFile(new_file_name);
	printf("Out File:%s\n",new_file_name);
}


void get_wprotect_sdk_address_elf(CELFFile & section,
                              BuildCodeInfo & build_info,
                              char *sz_sdk_begin_name,
                              char *sz_sdk_end_name)
{
  int section_count = section.GetSectionCount();
  for (int index = 0;index <  section_count;index++)
  {
      int sdk_begin_count = 0;
      int sdk_end_count = 0;
      int protect_begin_address = 0;
      int protect_end_address = 0;

      size_t section_size;
      unsigned char * ptr_section_data = (unsigned char*)section.GetSectionData(index,&section_size);
      printf("\nç¬¬%dä¸ªåŒºæ®µï¼Œå¤§å°%d\n",index,section_size);
      for (int offset = 0;offset < section_size;offset++)
      {
          //printf("%x ",(unsigned char)ptr_section_data[offset]);
          if ((offset + 1) % 16 == 0)
          {
            //  printf("\n");
          }
          if ((unsigned char)ptr_section_data[offset] == 0xeb
                  && sdk_begin_count==0
                  && sdk_end_count==0
                  && offset + max(strlen(sz_sdk_begin_name)+1,strlen(sz_sdk_end_name)+1) < section_size
                  )
          {
              sdk_begin_count++;
              sdk_end_count++;
              if (ptr_section_data[offset + sdk_begin_count] == strlen(sz_sdk_begin_name) + 1
                  && sdk_begin_count == 1)
              {
                  sdk_begin_count++;
                  sdk_end_count = 0;
                  continue;
              }
              else
              {
                  sdk_begin_count = 0;
              }
              if (ptr_section_data[offset + sdk_end_count] == strlen(sz_sdk_end_name) + 1
                  && sdk_end_count == 1)
              {
                  sdk_end_count++;
                  continue;
              }
              else
              {
                  sdk_end_count = 0;
              }

          }
          if (sdk_begin_count > 1)
          {
              if (ptr_section_data[offset + 1] == sz_sdk_begin_name[sdk_begin_count-2])
              {
                  sdk_begin_count++;
              }
              else
              {
                  sdk_begin_count = 0;
                  offset--;
                  continue;
              }

          }
          if (sdk_end_count > 1)
          {
              if (ptr_section_data[offset + 1] == sz_sdk_end_name[sdk_end_count-2])
              {
                  sdk_end_count++;
              }
              else
              {
                  sdk_end_count = 0;
                  offset--;
                  continue;
              }
          }
          if (sdk_begin_count == strlen(sz_sdk_begin_name) + 3)
          {
              int sdk_begin_str_size = strlen(sz_sdk_begin_name) + 1;
              printf("æ‰¾åˆ°SDK BEGIN offset:%x,addr:%x\n",
                     offset - sdk_begin_str_size,
                     section.GetSectionVa(index,offset - sdk_begin_str_size));
              protect_begin_address = section.GetSectionVa(index,offset - sdk_begin_str_size);
              memset((void*)section.GetSectionPtr(index,offset - sdk_begin_str_size),0x90,sdk_begin_count);
              sdk_begin_count = 0;

              //__asm__("int3");
          }
          if (sdk_end_count == strlen(sz_sdk_end_name) + 3)
          {
              printf("æ‰¾åˆ°SDK END offset:%x\n",offset - strlen(sz_sdk_end_name) - 1);
              int sdk_end_str_size = strlen(sz_sdk_end_name) + 1;
              protect_end_address = section.GetSectionVa(index,offset - sdk_end_str_size);
              if (protect_begin_address == 0 )
              {
                  printf("%xè¿™ä¸ªWProtect Endæ²¡æœ‰åŒ¹é…çš„WProtect Begin\n",protect_end_address);
              }
              else
              {
                  build_piece piece;
                  piece.build_exec_addr = protect_begin_address;
                  piece.build_exec_size = protect_end_address - protect_begin_address + sdk_end_str_size + 2;
                  printf("ä¿æŠ¤åœ°å€%x - %x\n",piece.build_exec_addr,piece.build_exec_addr+piece.build_exec_size);
                  build_info.push_back(piece);
              }
              protect_begin_address = 0;
              protect_end_address = 0;
              memset((void*)section.GetSectionPtr(index,offset - sdk_end_str_size),0x90,sdk_end_count);

              sdk_end_count = 0;
          }
          //printf("%x\n",offset);
          //printf("%x ",ptr_section_data[offset]);
          //if ((offset)%16==0)
          //{
          //    printf("\n");
          //}
      }
   }
  //throw;

}

void get_table_addr_elf(CELFFile &section, std::vector<long> & addr_table_entry,std::vector<long *> & addr_table_entry_point)
{
    for (std::vector<long>::iterator iter = addr_table_entry.begin();
         iter != addr_table_entry.end();iter++)
    {
        if (section.CheckAddressValidity(*iter))
        {
            long *addr = (long*)section.VaToPtr(*iter);
            //printf("table addr:%08x\r\n",*addr);
            if (addr)
            while (section.CheckAddressValidity(*addr))
            {
                printf ("table addr:%08x\n",*addr);
                addr_table_entry_point.push_back(addr);
                addr++;
            }
            //addr++;
        }
    }
}

void buildvmtest_elf(BuildCodeInfo & build_info) {
	VirtualMachineManage vm;
	CodeBufferInfo info;

	CELFFile file;

	char * build_exec_name = build_info.get_filename();
	bool b = file.LoadELFFile(build_exec_name);
	if (!b)
	{
		printf("file is not find\r\n");
		return;
	}
	get_wprotect_sdk_address_elf(file,build_info,"WProtect Begin","WProtect End");
	unsigned long section_size;

	VMAddressTable table(   file.GetNewSegmentSectionBase(),0x512,false);

	bool t_sign = table.get_sign();
	table.set_sign(true);
	long virtualmachine_address = table.assign_address(0x1024);
	table.set_sign(t_sign);
	VirtualMachine *pvm = vm.add_virtual_machine(virtualmachine_address,false);

	table.copy(virtualmachine_address,pvm->vm_info.buf,pvm->vm_info.size);

  for (BuildCodeInfo::iterator iter = build_info.begin(); iter != build_info.end(); iter++)
  {
    long build_exec_addr = iter->build_exec_addr;
    long build_exec_size = iter->build_exec_size;
    info.buf = file.VaToPtr(build_exec_addr);
    info.addr = build_exec_addr;
    info.size = 0x40194f - 0x4014a0;
    info.size = build_exec_size;
    if (info.size < 5)
    {
      printf("ç¼–è¯‘å†…å®¹ä¸èƒ½å°äºŽ5Byte,å®¹ä¸ä¸‹ä¸€ä¸ªè·³è½¬\n");
      return;
    }
//#define VM_DEBUG_BUILD
#ifdef VM_DEBUG_BUILD
    Analysis analysis;
    std::vector<CodePiece> code_list;
    analysis.disasm(&info,code_list);
    bool next = true;
    for (std::vector<CodePiece>::iterator iter = code_list.begin();
         iter != code_list.end();iter++)
    {
        bool begin = true;
        //info.addr = 0;
        //info.buf = 0;
        if (iter->get_is_jcc())
         info.size = iter->get_piece().back().insn_offset - iter->get_piece().front().insn_offset;
        else
         info.size = iter->get_piece().back().pc - iter->get_piece().front().insn_offset;
        info.addr = iter->get_piece().front().insn_offset;
        info.buf = section.VaToPtr(info.addr);

        if (info.size < 5 )
        {
            printf("ç¼–è¯‘çš„åœ°å€ä¸èƒ½å°äºŽ5Byte,è¿™æ®µæŒ‡ä»¤ç¼–è¯‘å¤±è´¥\n");
            //return;
            continue;
        }
        void * ptr_old_code = info.buf;
        size_t old_code_size = info.size;
        long old_addr = info.addr;
        BuildVMByteCode build(&vm,&info,&table);
        memset(ptr_old_code,0x90,old_code_size);
        add_jmp_addr(file,old_addr,info.addr);
    }
#else
    void * ptr_old_code = info.buf;
    size_t old_code_size = info.size;

    Analysis analysis;
    std::vector<long> addr_table;
    std::vector<long*> addr_entry_point;
    analysis.analysis_address_table(&info,addr_table,file.GetSectionMinAddress(),file.GetSectionMaxAddress());
    get_table_addr_elf(file,addr_table,addr_entry_point);

    BuildVMByteCode build(&vm,&info,&table,addr_entry_point);
    memset(ptr_old_code,0,old_code_size);
    add_jmp_addr_elf(file,build_exec_addr,info.addr);
#endif
  }


  FILE *pfile;

  //  VirtualMachine *pvm = vm.rand_virtual_machine();


  //t_sign = table.get_sign();
  //table.set_sign(true);
  //  long virtualmachine_address = table.assign_address(pvm->vm_info.size);
  //table.set_sign(t_sign);

  //  table.copy(virtualmachine_address,pvm->vm_info.buf,pvm->vm_info.size);

  section_size = (unsigned long)( table.buffer_size);
  file.AddSegmentSection(".WProtect",section_size,PF_X|PF_R|PF_W);
  file.WriteSegmentSectionData(file.GetProgramCount()-1,0,
      (unsigned char*)table.buffer,(unsigned long *)&table.buffer_size);
  char new_file_name[256];
  //memset(new_file_name,0,256);
  //memcpy(new_file_name,build_exec_name,strlen(build_exec_name)-3);
  strcpy(new_file_name,build_exec_name);
  strcat(new_file_name,"_WP");
  file.SavePEFile(new_file_name);
  printf("Out File:%s\n",new_file_name);
  //pfile = fopen( "virtualmachine","wb" );
  //fwrite( pvm->vm_info.buf,1,pvm->vm_info.size,pfile );
  //fclose( file );

  //delete [  ] buf;
}

int main(int argc, const char *argv[]) {

	if (1) {
		BuildCodeInfo build_pe("D:\\work\\jWProtect\\jwp\\hello.exe");
		buildvmtest(build_pe);
	} else {
		BuildCodeInfo build_elf_test("./helloWProtect_ELF");
		buildvmtest_elf(build_elf_test);
		CELFFile elf_file;
		if (elf_file.LoadELFFile("helloWProtect_ELF_WP"))
		//if (elf_file.LoadELFFile("elf_wprotect_WP"))
		if (elf_file.IsELFFile()) {
			printf("Section Count:%d,Program Count:%d\n",elf_file.GetSectionCount(),elf_file.GetProgramCount());
			for (int i = 0; i < elf_file.GetSectionCount();i++)
			{
				Elf32_Shdr * shdr =  elf_file.GetSectionHeader(i);
				printf("sh_name : %s\n", elf_file.GetStringTableStr( shdr->sh_name ));
				printf("sh_type : %#x\n", shdr->sh_type);
				printf("sh_flags : %d\n", shdr->sh_flags);
				printf("sh_addr : %#x\n", shdr->sh_addr);
				printf("sh_offset : %d\n", shdr->sh_offset);
				printf("sh_size : %d\n", shdr->sh_size);
				printf("sh_link : %d\n", shdr->sh_link);
				printf("sh_info : %d\n", shdr->sh_info);
				printf("sh_addralign : %d\n", shdr->sh_addralign);
				printf("sh_entsize : %d\n\n", shdr->sh_entsize);
			}
			for (int i = 0; i < elf_file.GetProgramCount();i++)
			{
				Elf32_Phdr *phdr = elf_file.GetProgramHeader(i);
				printf("p_paddr : %#x\n",phdr->p_paddr);
				printf("p_vaddr : %#x\n",phdr->p_vaddr);
				printf("p_align : %#d\n",phdr->p_align);
				printf("p_offset : %#x\n",phdr->p_offset);
				printf("p_type : %#d\n",phdr->p_type);
				printf("p_flags : %#d\n",phdr->p_flags);
				printf("p_filesz : %#x\n",phdr->p_filesz);
				printf("p_memsz : %#x\n\n",phdr->p_memsz);

			}
		}
	}

	return 1;
}
