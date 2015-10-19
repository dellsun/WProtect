/*
 *
 *   Copyrigth (C) Mon May 20 10:39:21 2013 XiaoWei
 *
 *                       handsomexiaowei@gmail.com
 *
 *
 */

#include "VirtualMachine.h"
//#include <time.h>
//#include <DataOperation.h>
#include "PCode.hpp"
#include <WProtectConfig.h>

VirtualMachine::VirtualMachine(long base)
{
  build_vm_handle(base);
}

VirtualMachine::VirtualMachine(long base,bool sign)
{
  handle.fuc_select.addorsub = sign;
  build_vm_handle(base);
}

VirtualMachine::~VirtualMachine()
{
  list <ppcode_block_info>::iterator iter;
  for (iter = pcode_list.begin(); iter != pcode_list.end(); ++iter)
  {
    ppcode_block_info info = *iter;
    delete info;
  }
  for (list <handle_info>::iterator iter = handle_info_list.begin(); iter != handle_info_list.end(); ++iter)
  {
    handle_info dv = *iter;
    for (list <encryption>::iterator eiter = dv.encode_key.begin(); eiter != dv.encode_key.end();++eiter) //删除encode对象
    {
      encryption en = *eiter;
      delete en.enfuc;
    }
    for (list <decryption>::iterator diter = dv.decode_key.begin(); diter != dv.decode_key.end();++diter) //删除decode对象
    {
      decryption de = *diter;
      delete de.defuc;
    }
    //delete dv.encode_key;
    // delete dv.decode_key;
  }
}


template <class T>
T * upset(T * t,int nSize)  //把数据乱序后返回  其他类无法调用 需要增加一个接口
{
	T *temp=new T[nSize];
	int nowsize=nSize;
	while (nowsize)
	{
		int rd=rand()%nowsize;
		temp[nSize-nowsize]=t[rd];
		nowsize--;
		for (int i = 0; i < nowsize - rd; i++)
		{
			t[rd+i]=t[rd+1+i];
		}
	}
	memcpy(t,temp,nSize * sizeof(T));
	return t;
}

typedef handle_info (VMHandle::*v_handle)();

void VirtualMachine::build_vm_handle(long base)
{
  handle_info info;
  unsigned long handle_count = 0;
  v_handle handle_array[]={
    &VMHandle::b_read_stack,
    &VMHandle::w_read_stack,
    &VMHandle::d_read_stack,
    
    &VMHandle::b_write_stack,
    &VMHandle::w_write_stack,
    &VMHandle::d_write_stack,
    
    &VMHandle::b_push_reg,
    &VMHandle::w_puah_reg,
    &VMHandle::d_push_reg,
   
    &VMHandle::b_pop_reg,
    &VMHandle::w_pop_reg,
    &VMHandle::d_pop_reg,
    
    &VMHandle::b_push_imm,
    &VMHandle::w_push_imm,
    &VMHandle::d_push_imm,
    
    &VMHandle::b_shl,
    &VMHandle::w_shl,
    &VMHandle::d_shl,
    
    &VMHandle::b_shr,
    &VMHandle::w_shr,
    &VMHandle::d_shr,
    
    &VMHandle::shld,
    &VMHandle::shrd,
    &VMHandle::b_nand,
    &VMHandle::w_nand,
    &VMHandle::d_nand,
    
    &VMHandle::set_pc,
    &VMHandle::ret,
    &VMHandle::in,
    &VMHandle::rdtsc,
    &VMHandle::cpuid,
    &VMHandle::check_stack,
    &VMHandle::push_stack_top_base,
    &VMHandle::b_read_mem,
    &VMHandle::w_read_mem,
    &VMHandle::d_read_mem,
   
    &VMHandle::b_write_mem,
    &VMHandle::w_write_mem,
    &VMHandle::d_write_mem,
    
    &VMHandle::pop_stack_top_base,
    &VMHandle::b_push_imm_sx,
    &VMHandle::w_push_imm_sx,
    
    &VMHandle::b_push_imm_zx,
    &VMHandle::w_push_imm_zx,
   
    &VMHandle::b_add,
    &VMHandle::w_add,
    &VMHandle::d_add,

    &VMHandle::b_rol,
    &VMHandle::w_rol,
    &VMHandle::d_rol,
    &VMHandle::b_ror,
    &VMHandle::w_ror,
    &VMHandle::d_ror
#ifdef PROTECT_X64
    ,&VMHandle::q_read_stack,
    &VMHandle::q_write_stack,
    &VMHandle::q_push_reg,
    &VMHandle::q_pop_reg,
    &VMHandle::q_push_imm,
    &VMHandle::q_shl,
    &VMHandle::q_shr,
    &VMHandle::q_nand,
    &VMHandle::q_read_mem,
    &VMHandle::q_write_mem,
    &VMHandle::d_push_imm_sx,
    &VMHandle::d_push_imm_zx,
    &VMHandle::q_add,
    &VMHandle::q_rol,
    &VMHandle::q_ror
#endif
  };
  handle_count = sizeof(handle_array) / sizeof (v_handle);
  upset<v_handle>(handle_array,handle_count);
  for (int i = 0; i < handle_count; i++)
  {
     v_handle r_fuc = handle_array[i];
    // printf("begin\r\n");
    info = (handle.*r_fuc)();
     //printf("end\r\n");
    handle_info_list.push_back(info);
  }

  long size = handle.a.getCodeSize();
#ifdef PROTECT_X64
  for (int i = 0; i < 0xff; i++)
  {
    handle.a.dq(rand());
  }
#else
  for (int i = 0; i < 0xff; i++)
  {
    handle.a.dd(rand());
  }
#endif
  dispatch_base = handle.a.getCodeSize() + base;
  handle.dispatch(base + size);
  full_handle_table(base,size);
  handle.a.relocCode(handle.a.getCode(),base);
  vm_info.base = base;
  vm_info.buf = handle.a.getCode();
  vm_info.size = handle.a.getCodeSize();
}

void VirtualMachine::add_pcode(AsmJit::Assembler &a,PCode *code,long base,long ret_address,long v_key,long decryption_key) //true表示正
{
  using namespace AsmJit;
  a.push(ret_address);
  a.push(v_key);
       a.pushf();
#ifndef PROTECT_X64
      a.pushad();
#else
      a.push(nax);
      a.push(ndx);
      a.push(ncx);
      a.push(nbx);
      a.push(nsp);
      a.push(nbp);
      a.push(nsi);
      a.push(ndi);
      a.push(r8);
      a.push(r9);
      a.push(r10);
      a.push(r11);
      a.push(r12);
      a.push(r13);
      a.push(r14);
      a.push(r15);
#endif
      a.mov(nbx,decryption_key);
      a.mov(nbp,nsp);
#ifndef PROTECT_X64
      a.sub(nsp,0xc0);
#else
      a.sub(nsp,0xc0 * 2);
#endif
      a.mov(ndi,nsp);
      if (code->pcode_info.sign)
        a.mov(nsi,base + 50);
      else
        a.mov(esi,base + 50 + code->pcode_info.offset);
      a.jmp(dispatch_base);
}

ppcode_block_info VirtualMachine::add_new_function(long base,PCode *code,long ret_address,long v_key,long decryption_key) //俩个key 一个是vm_context使用的 一个是ebx使用的解密Pcode key
{
  using namespace AsmJit;
  
  pcode_block_info *info = new pcode_block_info;
  info->entry = base;
  add_pcode(info->a,code,base,ret_address,v_key,decryption_key);
  if (code->pcode_info.sign)
  {
    info->pcode_base = base + 50;
    long init_handle_size = 50 - info->a.getCodeSize();
    for (int i = 0; i < init_handle_size; i++)
    {
      info->a.db(0xff & rand());
    }
    for (int i = 0; i < code->pcode_info.offset; i++)
    {
      info->a.db(code->pcode_info.buf[i]);
    }
    //return handle_offset;
  }
  else
  {
    info->pcode_base = base + 50 + code->pcode_info.offset;
    long init_handle_size = 50 - info->a.getCodeSize();
    for (int i = 0; i < init_handle_size; i++)
    {
      info->a.db(0xff & rand());
    }
    for (int i = code->pcode_info.size - code->pcode_info.offset; i < code->pcode_info.size; i++)
    {
      info->a.db(code->pcode_info.buf[i]);
    }
    //    return handle_offset;
  }
  info->a.relocCode(info->a.getCode(),base);
  info->buf = info->a.getCode();
  info->size = info->a.getCodeSize();
  pcode_list.push_back(info);
  
  /*
  long handle_offset = handle.a.getCodeSize();
  if (code->pcode_info.sign)
  {
    handle.initialization(base + 50);
    long init_handle_size = 50 - (handle.a.getCodeSize() - handle_offset);
    for (int i = 0; i < init_handle_size; i++)
    {
      handle.a.db(0xff & rand());
    }
    for (int i = 0; i < code->pcode_info.offset; i++)
    {
      handle.a.db(code->pcode_info.buf[i]);
    }
    //return handle_offset;
  }
  else
  {
    handle.initialization(base + 50 + code->pcode_info.offset); //50个byte是为这个handle预留的
    long init_handle_size = 50 - (handle.a.getCodeSize() - handle_offset);
    for (int i = 0; i < init_handle_size; i++)
    {
      handle.a.db(0xff & rand());
    }
    for (int i = code->pcode_info.size - code->pcode_info.offset; i < code->pcode_info.size; i++)
    {
      handle.a.db(code->pcode_info.buf[i]);
    }
    //    return handle_offset;
    }*/

  return info;
}


void VirtualMachine::full_handle_table(long base,long table_offset)
{
  unsigned char * asmbuf = handle.a.getCode();
  unsigned long * buf = (unsigned long *)(asmbuf + table_offset);
  unsigned long count = 0;
  for (list <handle_info>::iterator iter = handle_info_list.begin(); iter != handle_info_list.end(); ++iter)
  {
    handle_info info = *iter;
        if ( info.label == &handle.l_b_read_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_read_stack.handle = count++;
          handle_pcode.b_read_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_read_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_read_stack.handle = count++;
          handle_pcode.w_read_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_read_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_read_stack.handle = count++;
          handle_pcode.d_read_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_read_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_read_stack.handle = count++;
          handle_pcode.q_read_stack.encode_key = &info.encode_key;
        }  else  if ( info.label == &handle.l_b_write_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_write_stack.handle = count++;
          handle_pcode.b_write_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_write_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_write_stack.handle = count++;
          handle_pcode.w_write_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_write_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_write_stack.handle = count++;
          handle_pcode.d_write_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_write_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_write_stack.handle = count++;
          handle_pcode.q_write_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_push_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_push_reg.handle = count++;
          handle_pcode.b_push_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_push_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_push_reg.handle = count++;
          handle_pcode.w_push_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_push_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_push_reg.handle = count++;
          handle_pcode.d_push_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_push_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_push_reg.handle = count++;
          handle_pcode.q_push_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_pop_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_pop_reg.handle = count++;
          handle_pcode.b_pop_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_pop_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_pop_reg.handle = count++;
          handle_pcode.w_pop_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_pop_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_pop_reg.handle = count++;
          handle_pcode.d_pop_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_pop_reg )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_pop_reg.handle = count++;
          handle_pcode.q_pop_reg.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_push_imm )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_push_imm.handle = count++;
          handle_pcode.b_push_imm.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_push_imm )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_push_imm.handle = count++;
          handle_pcode.q_push_imm.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_push_imm )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_push_imm.handle = count++;
          handle_pcode.d_push_imm.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_push_imm )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_push_imm.handle = count++;
          handle_pcode.q_push_imm.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_shl )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_shl.handle = count++;
          handle_pcode.b_shl.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_shl )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_shl.handle = count++;
          handle_pcode.w_shl.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_shl )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_shl.handle = count++;
          handle_pcode.d_shl.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_shl )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_shl.handle = count++;
          handle_pcode.q_shl.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_shr )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_shr.handle = count++;
          handle_pcode.b_shr.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_shr )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_shr.handle = count++;
          handle_pcode.w_shr.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_shr )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_shr.handle = count++;
          handle_pcode.d_shr.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_shr )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_shr.handle = count++;
          handle_pcode.q_shr.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_shld )
        {
          buf[count] = info.offset + base;
          handle_pcode.shld.handle = count++;
          handle_pcode.shld.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_shrd )
        {
          buf[count] = info.offset + base;
          handle_pcode.shrd.handle = count++;
          handle_pcode.shrd.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_b_nand )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_nand.handle = count++;
          handle_pcode.b_nand.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_w_nand )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_nand.handle = count++;
          handle_pcode.w_nand.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_d_nand )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_nand.handle = count++;
          handle_pcode.d_nand.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_q_nand )
        {
          buf[count] = info.offset + base;
          handle_pcode.q_nand.handle = count++;
          handle_pcode.q_nand.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_set_pc )
        {
          buf[count] = info.offset + base;
          handle_pcode.set_pc.handle = count++;
          handle_pcode.set_pc.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_ret )
        {
          buf[count] = info.offset + base;
          handle_pcode.ret.handle = count++;
          handle_pcode.ret.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_in )
        {
          buf[count] = info.offset + base;
          handle_pcode.in.handle = count++;
          handle_pcode.in.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_rdtsc )
        {
          buf[count] = info.offset + base;
          handle_pcode.rdtsc.handle = count++;
          handle_pcode.rdtsc.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_cpuid )
        {
          buf[count] = info.offset + base;
          handle_pcode.cpuid.handle = count++;
          handle_pcode.cpuid.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_check_stack )
        {
          buf[count] = info.offset + base;
          handle_pcode.check_stack.handle = count++;
          handle_pcode.check_stack.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_dispatch )
        {
          buf[count] = info.offset + base;
          handle_pcode.dispatch.handle = count++;
          handle_pcode.dispatch.encode_key = &info.encode_key;
        } else  if ( info.label == &handle.l_push_stack_top_base )
        {
          buf[count] = info.offset + base;
          handle_pcode.push_stack_top_base.handle = count++;
          handle_pcode.push_stack_top_base.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_read_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.b_read_mem.handle = count++;
          handle_pcode.b_read_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_read_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.w_read_mem.handle = count++;
          handle_pcode.w_read_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_read_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.d_read_mem.handle = count++;
          handle_pcode.d_read_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_q_read_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.q_read_mem.handle = count++;
          handle_pcode.q_read_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_write_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.b_write_mem.handle = count++;
          handle_pcode.b_write_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_write_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.w_write_mem.handle = count++;
          handle_pcode.w_write_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_write_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.d_write_mem.handle = count++;
          handle_pcode.d_write_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_q_write_mem)
        {
          buf[count] = info.offset + base;
          handle_pcode.q_write_mem.handle = count++;
          handle_pcode.q_write_mem.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_push_imm_sx )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_push_imm_sx.handle = count++;
          handle_pcode.b_push_imm_sx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_push_imm_sx )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_push_imm_sx.handle = count++;
          handle_pcode.w_push_imm_sx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_push_imm_sx )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_push_imm_sx.handle = count++;
          handle_pcode.d_push_imm_sx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_push_imm_zx )
        {
          buf[count] = info.offset + base;
          handle_pcode.b_push_imm_zx.handle = count++;
          handle_pcode.b_push_imm_zx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_push_imm_zx )
        {
          buf[count] = info.offset + base;
          handle_pcode.w_push_imm_zx.handle = count++;
          handle_pcode.w_push_imm_zx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_push_imm_zx )
        {
          buf[count] = info.offset + base;
          handle_pcode.d_push_imm_zx.handle = count++;
          handle_pcode.d_push_imm_zx.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_pop_stack_top_base)
        {
          buf[count] = info.offset + base;
          handle_pcode.pop_stack_top_base.handle = count++;
          handle_pcode.pop_stack_top_base.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_add)
        {
          buf[count] = info.offset + base;
          handle_pcode.b_add.handle = count++;
          handle_pcode.b_add.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_add)
        {
          buf[count] = info.offset + base;
          handle_pcode.w_add.handle = count++;
          handle_pcode.w_add.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_add)
        {
          buf[count] = info.offset + base;
          handle_pcode.d_add.handle = count++;
          handle_pcode.d_add.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_q_add)
        {
          buf[count] = info.offset + base;
          handle_pcode.q_add.handle = count++;
          handle_pcode.q_add.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_rol)
        {
          buf[count] = info.offset + base;
          handle_pcode.b_rol.handle = count++;
          handle_pcode.b_rol.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_rol)
        {
          buf[count] = info.offset + base;
          handle_pcode.w_rol.handle = count++;
          handle_pcode.w_rol.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_rol)
        {
          buf[count] = info.offset + base;
          handle_pcode.d_rol.handle = count++;
          handle_pcode.d_rol.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_q_rol)
        {
          buf[count] = info.offset + base;
          handle_pcode.q_rol.handle = count++;
          handle_pcode.q_rol.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_b_ror)
        {
          buf[count] = info.offset + base;
          handle_pcode.b_ror.handle = count++;
          handle_pcode.b_ror.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_w_ror)
        {
          buf[count] = info.offset + base;
          handle_pcode.w_ror.handle = count++;
          handle_pcode.w_ror.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_d_ror)
        {
          buf[count] = info.offset + base;
          handle_pcode.d_ror.handle = count++;
          handle_pcode.d_ror.encode_key = &info.encode_key;
        } else if ( info.label == &handle.l_q_ror)
        {
          buf[count] = info.offset + base;
          handle_pcode.q_ror.handle = count++;
          handle_pcode.q_ror.encode_key = &info.encode_key;
        }
        
  }
}
