#include "BuildVMByteCode.hpp"
#include "VirtualMachine.h"
#include "CombosVMCode.hpp"
#include "VMAddressTable.hpp"
#include "VMCodeBuffer.hpp"
#include "PCode.hpp"
#include <WProtectConfig.h>
#include <Analysis.hpp>
#include <list>
#include <map>
#include <vector>
#include "OutDetailedInformation.hpp"


#define get_operand1_type(x) x.operand[0].type
#define get_operand2_type(x) x.operand[1].type
#define get_operand1(x) x.operand[0]
#define get_operand2(x) x.operand[1]
#define read_mem(x) if(x.type == UD_OP_MEM)\
        {\
              switch (x.size)\
              {\
                 case 8:\
                    var_combos_vm_code.b_read_mem();\
                    break;\
                 case 16:\
                    var_combos_vm_code.w_read_mem();\
                    break;\
                 case 32:\
                    var_combos_vm_code.d_read_mem();\
                    break;\
              }\        
        }    


#define write_mem(x) if(x.type == UD_OP_MEM)\
        {\
              switch (x.size)\
              {\
                 case 8:\
                    var_combos_vm_code.b_write_mem();\
                    break;\
                 case 16:\
                    var_combos_vm_code.w_write_mem();\
                    break;\
                 case 32:\
                    var_combos_vm_code.d_write_mem();\
                    break;\
              }\        
        }    
#define set_imm_operand_size(dst,src) if (dst.type == UD_OP_IMM)\
        {\
            switch (src.size)\
            {\
            case 8:\
                break;\
            case 16:\
                if (dst.size == 8)\
                dst.lval.sword = (signed short)dst.lval.sbyte;\
                break;\
            case 32:\
                if (dst.size == 8)\
                {\
                    dst.lval.sdword = (signed int)dst.lval.sbyte;\
                }\
                else if (dst.size == 16)\
                {\
                    dst.lval.sdword = (signed int)dst.lval.sword;\
                }\
                break;\
            }\
            dst.size = src.size;\
        }

 
void printf_map_register_store(std::map<int,RegisterStore> & _p_map,
        char *sz)
{/*{{{*/


    std::map<int,RegisterStore>::iterator iter = _p_map.begin();
    for (iter; iter!=_p_map.end();iter++)
    {
        printf("标签:%x\n",iter->first);
        printf("%s Key:%08x\n\n",sz,iter->second.get_key());
        OutDI di;
        di.set_begin_text(sz);
        di.set_end_text("\n");
        di.print_vmregister_information(iter->second);
    }
}/*}}}*/

long BuildVMByteCode::get_vmcode_address(int _label_index)
{
    long result = 0;
    if (var_map_label_vmcode_addr.find(_label_index) !=
            var_map_label_vmcode_addr.end())
    {
       result = var_map_label_vmcode_addr[_label_index];
    }
    return result;
}

//ret first_pcode  
long BuildVMByteCode::build_vmcode(bool b_allocator)
{
   long vm_byte_code_head  = 0;    
   newlabel_count = 0;
    for (std::vector<CodePiece>::iterator iter = var_list_code_piece.begin();
            iter != var_list_code_piece.end();iter++)
    {
        int var_cur_label = iter->get_label();
        VMCodeBufferManage * cur_vmbuffer_manage = NULL;
        if (b_allocator)
        {
           cur_vmbuffer_manage = new VMCodeBufferManage(ptr_vm);
           cur_vmbuffer_manage->set_vmcode_label(var_cur_label);
           var_vmcode_manager_list.push_back(cur_vmbuffer_manage); 
           var_map_label_vmbuffer_manage.insert(
                 std::make_pair<int,VMCodeBufferManage*>(
                    var_cur_label,cur_vmbuffer_manage));
        }
        else
        {
           if (var_map_label_vmbuffer_manage.find(var_cur_label)
                   != var_map_label_vmbuffer_manage.end())
           {
              cur_vmbuffer_manage = var_map_label_vmbuffer_manage[var_cur_label];
           }
           else
           {
              __asm("int3");
           }
        }

        
        PCode & var_pcode = cur_vmbuffer_manage->get_pcode();
        VCombosVMCode & var_combos_vm_code = cur_vmbuffer_manage->get_generator();
        VTable var_vmcode_info;
        if (b_allocator)
        {
           var_vmcode_info.key = var_pcode.get_original_key();
           var_vmcode_info.v = &var_combos_vm_code;   
           var_pcode.count_vmcode_begin();    
           var_pcode.set_key(0x12345678);
        }
        else
        {
#ifdef DEBUG
           char file_name[256];
           memset(&file_name,0,256);
           sprintf(file_name,"virtual_machine_assembly/Label%d,%08x\n", iter->get_label(),var_map_label_vmcode_addr[iter->get_label()]);
           var_pcode.out_log_file(file_name);      
#endif   
        }
          

        var_pcode.register_store_in = var_map_label_vmreg_store_in[iter->get_label()];  
        var_pcode.register_store_out = var_map_label_vmreg_store_out[iter->get_label()];
        var_combos_vm_code.save_vm_context();


        for (std::list<ud_t>::iterator uiter = iter->get_piece().begin();
                uiter != iter->get_piece().end();uiter++)
        {
           std::list<ud_t>::iterator uiter_check_end = uiter;
           if (++uiter_check_end == iter->get_piece().end()) //是否是最后一条指令
           {
              ///////////前缀处理
              if (uiter->pfx_repne || uiter->pfx_rep || uiter->pfx_repe)
              {
                 build_pfx(var_combos_vm_code,*uiter,*iter,b_allocator);
              }
              else
              ///////////前缀处理结束
             if (iter->get_is_jcc() == true) //是条件跳转指令
             {/*{{{*/
                bool test_find_addr_next = var_map_label_vmreg_store_in.find(iter->get_label() + 1) !=
                      var_map_label_vmreg_store_in.end() ;
                bool test_find_addr_jmp = var_map_label_vmreg_store_in.find(iter->get_jmplabel()) !=
                   var_map_label_vmreg_store_in.end();
                
                if (test_find_addr_next && test_find_addr_jmp)
                {
                   if (b_allocator)
                   {
                      var_combos_vm_code.d_push_imm(0);
                      var_combos_vm_code.d_push_imm(0); 
                   }
                   else
                   {
                      long next_addr = get_vmcode_address(iter->get_label() + 1); //var_map_label_vmcode_addr[iter->get_label() + 1];
                      long jmp_addr = get_vmcode_address(iter->get_jmplabel());//var_map_label_vmcode_addr[iter->get_jmplabel()];

                      var_combos_vm_code.d_push_imm(jmp_addr);
                      var_combos_vm_code.d_push_imm(next_addr);         
                   }
                   var_combos_vm_code.pop(T_NEXTINSADDR);
                   var_combos_vm_code.pop(T_JMPINSADDR);
                   build(var_combos_vm_code,*uiter);
                }
             }  /*}}}*/
             else //不是条件跳转指令
             {/*{{{*/
                if (b_allocator)
                {
                   var_combos_vm_code.d_push_imm(0); 
                }
                else
                {
                   long next_addr =  get_vmcode_address(iter->get_label() + 1);//var_map_label_vmcode_addr[iter->get_label() + 1];
                   var_combos_vm_code.d_push_imm(next_addr);   
                }
                var_combos_vm_code.pop(T_NEXTINSADDR);
                build(var_combos_vm_code,*uiter);
             }/*}}}*/

           }
           else
           {
              build(var_combos_vm_code,*uiter);
           }
           if (b_allocator == false)
           {
#ifdef DEBUG
              fprintf(var_pcode.get_log(),"\nbuild %-30s\n\n",uiter->insn_buffer);
              printf("build %-30s ...done\n",uiter->insn_buffer);   
#endif

           }     
           
           //printf("临时虚拟寄存器剩余:%d\n\n",var_combos_vm_code.get_tmp_vmregister_count());
        }

        /*if ( !(iter->get_jmplabel_type() != TYPE_LABEL &&
                iter->get_is_jcc() == false ))*/   //如果是ret之类的就不用恢复虚拟机上下文
        if (iter->get_jmplabel_type() != TYPE_RET)
        {
           var_combos_vm_code.recover_vm_context();                                                           
           var_combos_vm_code.push(T_NEXTINSADDR);
           var_combos_vm_code.set_pc(0x12345678);
        }
        else
        {
           //var_combos_vm_code.ret();
        }
        
        if (b_allocator)
        {
           size_t vm_piece_size = var_pcode.count_vmcode_end();  
           printf("标签%d,大小:%d\n",iter->get_label(),vm_piece_size);
           long t_byte_code_addr = ptr_addr_table->assign_address(vm_piece_size,var_vmcode_info);
           //long t_byte_code_addr = ptr_addr_table->assign_address(vm_piece_size); 
           if(vm_byte_code_head == 0)
              vm_byte_code_head = t_byte_code_addr;
           if (ptr_addr_table->get_sign())
               printf("分配到的PCODE地址%08x - %08x,标志:%d\n",
                  t_byte_code_addr,
                  t_byte_code_addr + vm_piece_size,
                  ptr_addr_table->get_sign());
           else
               printf("分配到的PCODE地址%08x - %08x,标志:%d\n",
                  t_byte_code_addr - vm_piece_size,
                  t_byte_code_addr,
                  ptr_addr_table->get_sign());

           var_map_label_vmcode_addr.insert(std::make_pair<int,long>(iter->get_label(),t_byte_code_addr));
        }

    }     
    return vm_byte_code_head;
}

BuildVMByteCode::BuildVMByteCode(VirtualMachineManage * ptr_vmmanage,
        pCodeBufferInfo ptr_info,
        VMAddressTable *ptr_address_table)
    :newlabel_count(0)
{
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RAX,T_RAX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RBX,T_RBX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RCX,T_RCX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RDX,T_RDX)); 
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RSP,T_RSP));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RBP,T_RBP));  
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RSI,T_RSI));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_RDI,T_RDI)); 
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_EAX,T_EAX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_EBX,T_EBX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_ECX,T_ECX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_EDX,T_EDX)); 
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_ESP,T_ESP));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_EBP,T_EBP));  
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_ESI,T_ESI));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_EDI,T_EDI));  
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_AX,T_AX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_BX,T_BX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_CX,T_CX));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_DX,T_DX)); 
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_SP,T_SP));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_BP,T_BP));  
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_SI,T_SI));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_DI,T_DI));   
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_AL,T_AL));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_AH,T_AH));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_BL,T_BL)); 
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_CL,T_CL));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_DL,T_DL));  
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_BH,T_BH));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_CH,T_CH));
    mapped_vm_register.insert(make_pair<ud_type,long>(UD_R_DH,T_DH));
    Analysis var_analysis;

    var_analysis.disasm(ptr_info,var_list_code_piece);
    var_analysis.printf_piece(var_list_code_piece);
    VirtualMachine *ptr_rand_vm = ptr_vmmanage->rand_virtual_machine();
    ptr_vm = ptr_rand_vm;
    ptr_addr_table = ptr_address_table;

    //printf_map_register_store(var_map_label_vmreg_store,"var_map_label_vmreg_store");

    full_register_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out);
    //printf_map_register_store(var_map_label_vmreg_store_in,"In  ");
    //printf_map_register_store(var_map_label_vmreg_store_out,"Out ");
    
    long vm_byte_code_head  = 0;
                
    vm_byte_code_head = build_vmcode(true);
    build_vmcode(false);
    ptr_address_table->copy();  
    long init_vm_key = 0x12345678;
    bool t_sign = ptr_address_table->get_sign();
    ptr_address_table->set_sign(true);
    long head_address = ptr_address_table->assign_address(0x70);
    ptr_address_table->set_sign(t_sign);
    ppcode_block_info info = ptr_rand_vm->create_function_head(head_address,
          vm_byte_code_head,
          &(var_vmcode_manager_list[0]->get_pcode()),
          ptr_info->addr + ptr_info->size,
          123456,
          init_vm_key); //pcode位置有问题

    ptr_address_table->copy(head_address,info->buf,info->size);
    
    ptr_info->addr = head_address; 
}



BuildVMByteCode::~BuildVMByteCode()
{
   for (std::vector<VMCodeBufferManage*>::iterator iter = var_vmcode_manager_list.begin();
         iter != var_vmcode_manager_list.end();iter++) 
   {
      delete *iter;
   }
}

void BuildVMByteCode::vm_operand(
      VCombosVMCode & var_combos_vm_code,
      ud_operand & var_operand)
{/*{{{*/
   var_combos_vm_code.impact_vmregister(false);
   switch (var_operand.type)
   {
      case UD_OP_MEM:
         {
            int count = 0;
            if (mapped_vm_register.find(var_operand.base) == mapped_vm_register.end())
            {
                 //printf("没有base\n");
            }
            else
            {
               long base = mapped_vm_register[var_operand.base];
               var_combos_vm_code.push(base); 
               count++;
            }
            if (mapped_vm_register.find(var_operand.index) == mapped_vm_register.end())
            {
               //printf("没有index\n");
            }
            else
            {
               long index = mapped_vm_register[var_operand.index];
               var_combos_vm_code.push(index);
               var_combos_vm_code.b_push_imm(var_operand.scale);
               var_combos_vm_code.d_shl(); 
               var_combos_vm_code.pop(T_INVALID);
               count++;
            }
            if (var_operand.lval.sdword)
            {
               count++;
               if (var_operand.offset == 8)
               {
                  signed char lval = var_operand.lval.sbyte;
                  var_combos_vm_code.d_push_imm(lval);
               }
               else
               {
                  long lval = var_operand.lval.sdword;
                  var_combos_vm_code.d_push_imm(lval);
               }
            }
            for (int i = 1; i < count ; i++)
            {
               var_combos_vm_code.d_add();
               var_combos_vm_code.pop(T_INVALID);
            }
            /*switch (var_operand.size)
            {
               case 8:
                  var_combos_vm_code.b_read_mem();
                  break;
               case 16:
                  var_combos_vm_code.w_read_mem();
                  break;
               case 32:
                  var_combos_vm_code.d_read_mem();
                  break;
            } */
              
         }
         break;
      case UD_OP_IMM:
         {
            switch (var_operand.size)
            {
               case 8:
                  {
                     signed char lval = var_operand.lval.sbyte; 
                     var_combos_vm_code.b_push_imm(lval);
                  }
                  break;
               case 16:
                  {
                     signed short lval = var_operand.lval.sword;
                     var_combos_vm_code.w_push_imm(lval); 
                  }
                  break;
               case 32:
                  {
                     int lval = var_operand.lval.sdword;
                     var_combos_vm_code.d_push_imm(lval);  
                  }
                  break;
            }
         }
         break;
      case UD_OP_REG:
         {
            if (mapped_vm_register.find(var_operand.base) == mapped_vm_register.end())
            {
                 printf("没有寄存器\n");
                 __asm("int3");
            }
            else
            {
               long base = mapped_vm_register[var_operand.base];
               var_combos_vm_code.push(base); 
            } 
         }
         break;
   }
   var_combos_vm_code.impact_vmregister(true);
}/*}}}*/

long BuildVMByteCode::get_vm_register(ud_type _register)
{/*{{{*/
   long result = T_INVALID;
   if (mapped_vm_register.find(_register) == mapped_vm_register.end())
   {
      printf("无法识别的寄存器\n");
   }
   else
   {
      result = mapped_vm_register[_register];
   }
   return result;
}/*}}}*/



/*
void BuildVMByteCode::build(VCombosVMCode & var_combos_vm_code,ud_t &var_ud)
{
  build(var_combos_vm_code,var_ud,0);
} 
*/

 //编译前缀
void BuildVMByteCode::build_pfx(VCombosVMCode & var_combos_vm_code,ud_t &var_ud,CodePiece & var_cur_piece,bool b_allocator)
{
   VMCodeBufferManage * code_buf = NULL;

   if (b_allocator)
   {
      code_buf = create_newvm_piece();
   }
   else
   {
      /*if (var_map_newlabel_vmbuffer_manage.find(newlabel_count) !=
            var_map_newlabel_vmbuffer_manage.end())
      {
         code_buf = var_map_newlabel_vmbuffer_manage[newlabel_count];
      }*/
       code_buf = get_newvm_piece();
   }

   VCombosVMCode & new_combos_vm_code = code_buf->get_generator();
   PCode & new_pcode = code_buf->get_pcode();

   if (b_allocator)
   {
       new_pcode.count_vmcode_begin();
       //cur_vmcode -> new_combos or next
       //new_combos -> cur_vmcode

       RegisterStore t_store;
       new_combos_vm_code.upset_register_array(t_store);

       new_combos_vm_code.set_vmregister_store_in(t_store);
       new_combos_vm_code.set_vmregister_store_out(t_store);
       new_pcode.set_key(0x12345678);
   }
   else
   {
       new_combos_vm_code.set_vmregister_store_in(
                   var_map_label_vmreg_store_out[var_cur_piece.get_label()]);
       new_combos_vm_code.set_vmregister_store_out(
                   var_map_label_vmreg_store_in[var_cur_piece.get_label()]);
#ifdef DEBUG
           char file_name[256];
           memset(&file_name,0,256);
           sprintf(file_name,"virtual_machine_assembly/NewLabel%d,%08x\n", get_newvm_cur_label(),var_map_newlabel_vmcode_addr[get_newvm_cur_label()]);
           new_pcode.out_log_file(file_name);
#endif


   }
   new_combos_vm_code.save_vm_context();
   build(new_combos_vm_code,var_ud); 
   
   //new_combos_vm_code.d_push_imm(0);
   //new_combos_vm_code.set_key(0);


   if (var_ud.pfx_rep)
   {
      if (b_allocator)
      {
       var_combos_vm_code.d_push_imm(0);
       var_combos_vm_code.d_push_imm(0);
      } else {
         long jmp_addr = var_map_label_vmcode_addr[var_cur_piece.get_jmplabel()];
         long next_addr = var_map_newlabel_vmcode_addr[get_newvm_cur_label()];
         //var_combos_vm_code.d_push_imm(next_addr);
         //var_combos_vm_code.d_push_imm(jmp_addr);
         var_combos_vm_code.d_push_imm(jmp_addr);
         var_combos_vm_code.d_push_imm(next_addr);
      }
      //var_combos_vm_code.ptr_pcode->out_info("cmp ecx,0 \njz store\n");
      var_combos_vm_code.impact_vmregister(false);
      var_combos_vm_code.push_vsp();

      var_combos_vm_code.push(T_ECX); //cmp ecx,0
      var_combos_vm_code.d_push_imm(0);
      var_combos_vm_code.d_cmp();
      var_combos_vm_code.get_zf();

      var_combos_vm_code.d_add();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.d_read_mem(); //读取地址
      var_combos_vm_code.pop(T_NEXTINSADDR);
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_INVALID);

      //用这个的话计算到最后ecx会少一个
      /*
      var_combos_vm_code.d_push_imm(1) ;
      var_combos_vm_code.push(T_ECX); //sub ecx,1
      var_combos_vm_code.d_sub();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_ECX);

      */
      new_combos_vm_code.d_push_imm(1);
      new_combos_vm_code.push(T_ECX); //sub ecx,1
      new_combos_vm_code.d_sub();
      new_combos_vm_code.pop(T_INVALID);
      new_combos_vm_code.pop(T_ECX);



      //var_combos_vm_code.set_pc(0x12345678);

      new_combos_vm_code.recover_vm_context();
      if (b_allocator)
      {
          new_combos_vm_code.d_push_imm(0);
          //new_combos_vm_code.d_push_imm(0);
      }
      else
      {
          int next_addr = get_vmcode_address(var_cur_piece.get_label());//var_map_label_vmcode_addr[var_cur_piece.get_label()];
          new_combos_vm_code.d_push_imm(next_addr);
      }
      new_combos_vm_code.set_pc(0x12345678);

   }
   else if (var_ud.pfx_repe)
   {
      //while (ecx != 0)
      //{
      //   oldcode();
      //}
      if (b_allocator)
      {
       var_combos_vm_code.d_push_imm(0);
       var_combos_vm_code.d_push_imm(0);
      } else {
         long jmp_addr = var_map_label_vmcode_addr[var_cur_piece.get_jmplabel()];
         long next_addr = var_map_newlabel_vmcode_addr[get_newvm_cur_label()];
         var_combos_vm_code.d_push_imm(next_addr);
         var_combos_vm_code.d_push_imm(jmp_addr);
         //var_combos_vm_code.d_push_imm(jmp_addr);
         //var_combos_vm_code.d_push_imm(next_addr);
      }
      //var_combos_vm_code.ptr_pcode->out_info("cmp ecx,0 \njz store\n");
      var_combos_vm_code.impact_vmregister(false);
      var_combos_vm_code.push_vsp();

      var_combos_vm_code.push(T_ECX); //cmp ecx,0
      var_combos_vm_code.d_push_imm(0);
      var_combos_vm_code.d_cmp();
      var_combos_vm_code.get_zf();

      var_combos_vm_code.push(T_FLAG);
      var_combos_vm_code.impact_vmregister(true);
      var_combos_vm_code.get_zf();
      var_combos_vm_code.d_or();
      var_combos_vm_code.pop(T_INVALID);

      var_combos_vm_code.d_add();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.d_read_mem(); //读取地址
      //var_combos_vm_code.int3();
      var_combos_vm_code.pop(T_NEXTINSADDR);
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_INVALID);

      //用这个的话计算到最后ecx会少一个
      /*
      var_combos_vm_code.d_push_imm(1) ;
      var_combos_vm_code.push(T_ECX); //sub ecx,1
      var_combos_vm_code.d_sub();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_ECX);

      */
      new_combos_vm_code.d_push_imm(1);
      new_combos_vm_code.push(T_ECX); //sub ecx,1
      new_combos_vm_code.d_sub();
      new_combos_vm_code.pop(T_INVALID);
      new_combos_vm_code.pop(T_ECX);


      //var_combos_vm_code.set_pc(0x12345678);

      new_combos_vm_code.recover_vm_context();
      if (b_allocator)
      {
          new_combos_vm_code.d_push_imm(0);
          //new_combos_vm_code.d_push_imm(0);
      }
      else
      {
          int next_addr = get_vmcode_address(var_cur_piece.get_label());//var_map_label_vmcode_addr[var_cur_piece.get_label()];
          new_combos_vm_code.d_push_imm(next_addr);
      }
      new_combos_vm_code.set_pc(0x12345678);

   }
   else if (var_ud.pfx_repne)
   {
      
      //while (ecx != 0)
      //{
      //   oldcode();
      //}
      if (b_allocator)
      {
       var_combos_vm_code.d_push_imm(0);
       var_combos_vm_code.d_push_imm(0);
      } else {
         long jmp_addr = var_map_label_vmcode_addr[var_cur_piece.get_jmplabel()];
         long next_addr = var_map_newlabel_vmcode_addr[get_newvm_cur_label()];
         //var_combos_vm_code.d_push_imm(next_addr);
         //var_combos_vm_code.d_push_imm(jmp_addr);
         var_combos_vm_code.d_push_imm(jmp_addr);
         var_combos_vm_code.d_push_imm(next_addr);
      } 
      //var_combos_vm_code.ptr_pcode->out_info("cmp ecx,0 \njz store\n");
      var_combos_vm_code.impact_vmregister(false);
      var_combos_vm_code.push_vsp();

      var_combos_vm_code.push(T_ECX); //cmp ecx,0
      var_combos_vm_code.d_push_imm(0);
      var_combos_vm_code.d_cmp();
      var_combos_vm_code.get_zf();

      var_combos_vm_code.push(T_FLAG);
      var_combos_vm_code.impact_vmregister(true);
      var_combos_vm_code.get_zf();
      var_combos_vm_code.d_or();
      var_combos_vm_code.pop(T_INVALID);

      var_combos_vm_code.d_add();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.d_read_mem(); //读取地址
      //var_combos_vm_code.int3();
      var_combos_vm_code.pop(T_NEXTINSADDR);
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_INVALID);

      //用这个的话计算到最后ecx会少一个
      /*
      var_combos_vm_code.d_push_imm(1) ;
      var_combos_vm_code.push(T_ECX); //sub ecx,1
      var_combos_vm_code.d_sub();
      var_combos_vm_code.pop(T_INVALID);
      var_combos_vm_code.pop(T_ECX);

      */
      new_combos_vm_code.d_push_imm(1);
      new_combos_vm_code.push(T_ECX); //sub ecx,1
      new_combos_vm_code.d_sub();
      new_combos_vm_code.pop(T_INVALID);
      new_combos_vm_code.pop(T_ECX);


      //var_combos_vm_code.set_pc(0x12345678);

      new_combos_vm_code.recover_vm_context();
      if (b_allocator)
      {
          new_combos_vm_code.d_push_imm(0);
          //new_combos_vm_code.d_push_imm(0);
      }
      else
      {
          int next_addr = get_vmcode_address(var_cur_piece.get_label());//var_map_label_vmcode_addr[var_cur_piece.get_label()];
          new_combos_vm_code.d_push_imm(next_addr);
      }
      new_combos_vm_code.set_pc(0x12345678);

      //var_combos_vm_code.push()
      //var_combos_vm_code
   }
   if (b_allocator)
   {
      int new_pcode_size = new_pcode.count_vmcode_end();
      VTable table;
      table.v = &new_combos_vm_code;
      long new_pcode_addr = ptr_addr_table->assign_address(new_pcode_size,table);
      var_map_newlabel_vmcode_addr.insert(std::make_pair<int,long>(get_newvm_cur_label(),new_pcode_addr));
      //printf("NewLabel分配到PCODE地址:%x - %x\n",new_pcode_addr - new_pcode_size,new_pcode_addr);
           if (ptr_addr_table->get_sign())
               printf("分配到的NEWPCODE地址%08x - %08x,标志:%d\n",
                  new_pcode_addr,
                  new_pcode_addr + new_pcode_size,
                  ptr_addr_table->get_sign());
           else
               printf("分配到的NEWPCODE地址%08x - %08x,标志:%d\n",
                  new_pcode_addr - new_pcode_size,
                  new_pcode_addr,
                  ptr_addr_table->get_sign());

   }
   else
   {
       //ptr_addr_table->copy();
       //int a = new_combos_vm_code.get_code_size();
       //printf("代码大小%d\n",a);
   }


   //newlabel_count++;
}

VMCodeBufferManage * BuildVMByteCode::create_newvm_piece()
{
   var_vmcode_manager_list.push_back(new VMCodeBufferManage(ptr_vm));
   var_map_newlabel_vmbuffer_manage.insert(
         std::make_pair<int,VMCodeBufferManage *>(newlabel_count,var_vmcode_manager_list.back()));
   newlabel_count++;
   return var_vmcode_manager_list.back();
} 

VMCodeBufferManage * BuildVMByteCode::get_newvm_piece()
{
    VMCodeBufferManage * result = NULL;
   if (var_map_newlabel_vmbuffer_manage.find(newlabel_count) !=
           var_map_newlabel_vmbuffer_manage.end())
   {
       result = var_map_newlabel_vmbuffer_manage[newlabel_count];

   }
   newlabel_count++;
   return result;
}

long BuildVMByteCode::get_newvm_cur_label()
{
    return newlabel_count;
}

void BuildVMByteCode::write_vm_operand(VCombosVMCode & var_combos_vm_code,ud_operand & var_operand)
{
        switch (var_operand.type)
        {
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,var_operand);
              write_mem(var_operand);
              break;
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(var_operand.base));
              break;
        }    
}

void BuildVMByteCode::build(VCombosVMCode & var_combos_vm_code,ud_t &var_ud)
{/*{{{*/
   if(get_operand1(var_ud).base == UD_R_ESP ||
         get_operand1(var_ud).index == UD_R_ESP ||
         get_operand2(var_ud).base == UD_R_ESP ||
         get_operand2(var_ud).index == UD_R_ESP)
   {
      var_combos_vm_code.push_vsp();
      var_combos_vm_code.pop(T_ESP);
   }
   switch(var_ud.mnemonic)
   {
    case UD_Imov:
       {/*{{{*/
          set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));

           vm_operand(var_combos_vm_code,get_operand2(var_ud));
           if (get_operand2_type(var_ud) == UD_OP_MEM)
           {
              switch (get_operand2(var_ud).size)
              {
                 case 8:
                    var_combos_vm_code.b_read_mem();
                    break;
                 case 16:
                    var_combos_vm_code.w_read_mem();
                    break;
                 case 32:
                    var_combos_vm_code.d_read_mem();
                    break;
              }        
           }
           if (get_operand1_type(var_ud) == UD_OP_REG)
           {
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud).base));
           } else if (get_operand1_type(var_ud) == UD_OP_MEM)
           {
              vm_operand(var_combos_vm_code,get_operand1(var_ud));
              switch (get_operand1(var_ud).size)
              {
                 case 8:
                    var_combos_vm_code.b_write_mem();
                    break;
                 case 16:
                    var_combos_vm_code.w_write_mem();
                    break;
                 case 32:
                    var_combos_vm_code.d_write_mem();
                    break;
              }
           }
       }/*}}}*/
     break;
    case UD_Ilea:
     {/*{{{*/
        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        
        var_combos_vm_code.pop(mapped_vm_register[get_operand1(var_ud).base]);
     }/*}}}*/
     break;
    case UD_Ipush:
     {/*{{{*/
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        /*if (get_operand1_type(var_ud) == UD_OP_MEM)
        {
              switch (get_operand1(var_ud).size)
              {
                 case 8:
                    var_combos_vm_code.b_read_mem();
                    break;
                 case 16:
                    var_combos_vm_code.w_read_mem();
                    break;
                 case 32:
                    var_combos_vm_code.d_read_mem();
                    break;
              }        
        }*/
        read_mem(get_operand1(var_ud));
     }/*}}}*/
     break;   
    case UD_Icmp:
     {/*{{{*/
/*操作
temp  SRC1 - SignExtend(SRC2); 
ModifyStatusFlags; (* Modify status flags in the same manner as the SUB instruction*)
影响的标志
CF、OF、SF、ZF、AF 及 PF 标志根据结果设置。
*/      set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));

        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_sub();
              var_combos_vm_code.pop(T_FLAG);   
              var_combos_vm_code.pop(T_INVALID | T_E32X | T_16X | T_8L);
              break;
           case 16:
              var_combos_vm_code.w_sub();
              var_combos_vm_code.pop(T_FLAG);
              var_combos_vm_code.pop(T_INVALID | T_E32X | T_16X);
              break;
           case 32:
              var_combos_vm_code.d_sub();
              var_combos_vm_code.pop(T_FLAG);
              var_combos_vm_code.pop(T_INVALID | T_E32X);
              break;
        }
        
     }/*}}}*/
     break;     
    case UD_Iret:
     {/*{{{*/
        var_combos_vm_code.ret();
     }/*}}}*/
     break;
    case UD_Iadd:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));

        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));

        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_add();
              break;
           case 16:
              var_combos_vm_code.w_add();
              break;
           case 32:
              var_combos_vm_code.d_add();
              break;
        }
        var_combos_vm_code.pop(T_FLAG);

        switch (get_operand1_type(var_ud))
        {
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,get_operand1(var_ud));  
              write_mem(get_operand1(var_ud));
              break;
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud).base));
              break;
        }
        //write_mem(get_operand1(var_ud));
     }/*}}}*/
     break;
    case UD_Isub:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));

        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_sub();
              break;
           case 16:
              var_combos_vm_code.w_sub();
              break;
           case 32:
              var_combos_vm_code.d_sub();
              break;
        }
        var_combos_vm_code.pop(T_FLAG);
        
        switch(get_operand1_type(var_ud))
        {
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,get_operand1(var_ud)); 
              write_mem(get_operand1(var_ud));    
              break;
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud).base));
              break;
        }
        
     }/*}}}*/
     break;
    case UD_Inot:
     {/*{{{*/
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_not();
              break;
           case 16:
              var_combos_vm_code.w_not();
              break;
           case 32:
              var_combos_vm_code.d_not();
              break;
        }
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
        /*
        switch (get_operand1_type(var_ud))
        {
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,get_operand1(var_ud));
              write_mem(get_operand1(var_ud));
              break;
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud)));
              break;
        } */
        write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
     }/*}}}*/
     break;
    case UD_Iand:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));

        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_and();
              break;
           case 16:
              var_combos_vm_code.w_and();
              break;
           case 32:
              var_combos_vm_code.d_and();
              break;
        }
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
 
        write_vm_operand(var_combos_vm_code,get_operand1(var_ud)); 
     }/*}}}*/
     break;
    case UD_Ixor:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_xor();
              break;
           case 16:
              var_combos_vm_code.w_xor();
              break;
           case 32:
              var_combos_vm_code.d_xor();
              break;
        }
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
 
        write_vm_operand(var_combos_vm_code,get_operand1(var_ud));  
     }/*}}}*/
     break;
    case UD_Ior:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_or();
              break;
           case 16:
              var_combos_vm_code.w_or();
              break;
           case 32:
              var_combos_vm_code.d_or();
              break;
        }
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
 
        write_vm_operand(var_combos_vm_code,get_operand1(var_ud));   
     }/*}}}*/
     break;
    case UD_Itest:
     {/*{{{*/
        set_imm_operand_size(get_operand2(var_ud),get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        vm_operand(var_combos_vm_code,get_operand2(var_ud));
        read_mem(get_operand2(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.b_and();
              break;
           case 16:
              var_combos_vm_code.w_and();
              break;
           case 32:
              var_combos_vm_code.d_and();
              break;
        }
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
        switch (get_operand1(var_ud).size)
        {
           case 8:
              var_combos_vm_code.pop(T_INVALID|T_8H);
              break;
           case 16:
              var_combos_vm_code.pop(T_INVALID|T_16X);
              break;
           case 32:
              var_combos_vm_code.pop(T_INVALID|T_E32X);
              break;
        }
     }/*}}}*/
     break;
    case UD_Ipop:
     {/*{{{*/
        //vm_operand(var_combos_vm_code,get_operand1(var_ud));
        write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
        //write_mem(get_operand1(var_ud));
        //if (get_operand1_type(var_ud) )
        //var_combos_vm_code.pop
     }/*}}}*/
     break;
    case UD_Iinc:
     {/*{{{*/


        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8: 
              var_combos_vm_code.b_push_imm(1);
              var_combos_vm_code.b_add();
              break;
           case 16:
              var_combos_vm_code.w_push_imm(1);
              var_combos_vm_code.w_add();
              break;
           case 32:
              var_combos_vm_code.d_push_imm(1);
              var_combos_vm_code.d_add();
              break;
        }
        var_combos_vm_code.d_push_imm(~((1 << 0) | (1 << 10)));
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
              
        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm((1 << 0) | (1 << 10));
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);     
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
        //var_combos_vm_code.pop(T_FLAG);
        var_combos_vm_code.popf();
        switch (get_operand1_type(var_ud))
        {
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud).base));
              break;
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,get_operand1(var_ud));
              write_mem(get_operand1(var_ud));
              break;
        }
     }/*}}}*/
     break;
    case UD_Idec:
     {/*{{{*/

        vm_operand(var_combos_vm_code,get_operand1(var_ud));
        read_mem(get_operand1(var_ud));
        switch (get_operand1(var_ud).size)
        {
           case 8: 
              var_combos_vm_code.b_push_imm(1);
              var_combos_vm_code.b_sub();
              break;
           case 16:
              var_combos_vm_code.w_push_imm(1);
              var_combos_vm_code.w_sub();
              break;
           case 32:
              var_combos_vm_code.d_push_imm(1);
              var_combos_vm_code.d_sub();
              break;
        }
        var_combos_vm_code.d_push_imm(~((1 << 0) | (1 << 10)));
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
              
        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm((1 << 0) | (1 << 10));
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);     
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_FLAG); 
        switch (get_operand1_type(var_ud))
        {
           case UD_OP_REG:
              var_combos_vm_code.pop(get_vm_register(get_operand1(var_ud).base));
              break;
           case UD_OP_MEM:
              vm_operand(var_combos_vm_code,get_operand1(var_ud));
              write_mem(get_operand1(var_ud));
              break;
        }    
     }/*}}}*/
     break;
    case UD_Ishl:
     {
         vm_operand(var_combos_vm_code, get_operand1(var_ud));
         read_mem(get_operand1(var_ud));
         vm_operand(var_combos_vm_code, get_operand2(var_ud));
         read_mem(get_operand2(var_ud));
         switch (get_operand1(var_ud).size) {
         case 8:
             var_combos_vm_code.b_shl();
             break;
         case 16:
             var_combos_vm_code.w_shl();
             break;
         case 32:
             var_combos_vm_code.d_shl();
             break;
         default:
             break;
         }
         //var_combos_vm_code.pop(T_FLAG);
         var_combos_vm_code.popf();
         write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
     }
     break;
    case UD_Ishr:
     {
         vm_operand(var_combos_vm_code, get_operand1(var_ud));
         read_mem(get_operand1(var_ud));
         vm_operand(var_combos_vm_code, get_operand2(var_ud));
         read_mem(get_operand2(var_ud));
         switch (get_operand1(var_ud).size) {
         case 8:
             var_combos_vm_code.b_shr();
             break;
         case 16:
             var_combos_vm_code.w_shr();
             break;
         case 32:
             var_combos_vm_code.d_shr();
             break;
         default:
             break;
         }
         //var_combos_vm_code.pop(T_FLAG);
         var_combos_vm_code.popf();
         write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
     }
     break;
    case UD_Isar:
     {
       /*
        * sar 10101110,2
        * 最高位 = 1
        * 11111111  sub 0,最高位 -> diff
        * 11111000  shl diff << 右移位数 + 1
        * 11111001  add diff,最高位
        * 00000111  neg diff
        * 11100000  shl diff,目标操作数位数(7) - 右移位数 + 1
        * shr 目标操作数,右移位数
        * add 目标操作数,diff
        */
         var_combos_vm_code.impact_vmregister(false);

         vm_operand(var_combos_vm_code, get_operand1(var_ud));
         read_mem(get_operand1(var_ud));
         int dest_reg = var_combos_vm_code.get_tmp_vmregister();
         int highest_bit = var_combos_vm_code.get_tmp_vmregister();
         int count_reg = var_combos_vm_code.get_tmp_vmregister();
         vm_operand(var_combos_vm_code, get_operand2(var_ud));
         read_mem(get_operand2(var_ud));
         switch (get_operand1(var_ud).size) {
         case 8:
             var_combos_vm_code.pop(count_reg|T_E32X|T_16X|T_8H);//save count
             //and o1,10000000b
             var_combos_vm_code.push_vsp();
             var_combos_vm_code.b_read_mem(); //copy dest
             var_combos_vm_code.pop(dest_reg|T_E32X|T_16X|T_8H); //save dest
             var_combos_vm_code.b_push_imm(1<<7);
             var_combos_vm_code.b_and();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.b_push_imm(7);
             var_combos_vm_code.b_shr();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.push_vsp();
             var_combos_vm_code.b_read_mem();
             var_combos_vm_code.pop(highest_bit|T_E32X|T_16X|T_8H);
             //neg diff
             var_combos_vm_code.b_neg();
             var_combos_vm_code.pop(T_INVALID);
             //add count,1
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(1);
             var_combos_vm_code.b_add();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,count+1
             var_combos_vm_code.b_shl();
             var_combos_vm_code.pop(T_INVALID);
             //add diff,最高位
             var_combos_vm_code.push(highest_bit|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_add();
             var_combos_vm_code.pop(T_INVALID);
             //neg diff
             var_combos_vm_code.b_neg();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,7 - count_reg
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(8-1);
             var_combos_vm_code.b_sub();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.b_shl();
             var_combos_vm_code.pop(T_INVALID);
             //shr dest_reg,count_reg
             var_combos_vm_code.push(dest_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_shr();
             var_combos_vm_code.pop(T_INVALID);
             //add dest_reg,diff
             var_combos_vm_code.b_or();
             var_combos_vm_code.popf();
             write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
             break;
         case 16:
             var_combos_vm_code.pop(count_reg|T_E32X|T_16X|T_8H);//save count
             //and o1,10000000b
             var_combos_vm_code.push_vsp();
             var_combos_vm_code.w_read_mem(); //copy dest
             var_combos_vm_code.pop(dest_reg|T_E32X|T_16X); //save dest
             var_combos_vm_code.w_push_imm(1<<15);
             var_combos_vm_code.w_and();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.b_push_imm(15);
             var_combos_vm_code.w_shr();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.push_vsp();
             var_combos_vm_code.w_read_mem();
             var_combos_vm_code.pop(highest_bit|T_E32X|T_16X);
             //neg diff
             var_combos_vm_code.w_neg();
             var_combos_vm_code.pop(T_INVALID);
             //add count,1
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(1);
             var_combos_vm_code.b_add();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,count+1
             var_combos_vm_code.w_shl();
             var_combos_vm_code.pop(T_INVALID);
             //add diff,最高位
             var_combos_vm_code.push(highest_bit|T_E32X|T_16X);
             var_combos_vm_code.w_add();
             var_combos_vm_code.pop(T_INVALID);
             //neg diff
             var_combos_vm_code.w_neg();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,7 - count_reg
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(16-1);
             var_combos_vm_code.b_sub();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.w_shl();
             var_combos_vm_code.pop(T_INVALID);
             //shr dest_reg,count_reg
             var_combos_vm_code.push(dest_reg|T_E32X|T_16X);
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.w_shr();
             //var_combos_vm_code.pop(T_FLAG);
             var_combos_vm_code.popf();
             //add dest_reg,diff
             var_combos_vm_code.w_or();
             var_combos_vm_code.pop(T_INVALID);
             write_vm_operand(var_combos_vm_code,get_operand1(var_ud));
             break;
         case 32:
             var_combos_vm_code.pop(count_reg|T_E32X|T_16X|T_8H);//save count
             //and o1,10000000b
             var_combos_vm_code.push_vsp();
             var_combos_vm_code.d_read_mem(); //copy dest
             var_combos_vm_code.pop(dest_reg|T_E32X); //save dest
             var_combos_vm_code.d_push_imm(1<<31);
             var_combos_vm_code.d_and();
             var_combos_vm_code.pop(T_INVALID);

             //shr o1,31
             var_combos_vm_code.b_push_imm(31);
             var_combos_vm_code.d_shr();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.push_vsp();
             var_combos_vm_code.d_read_mem();
             var_combos_vm_code.pop(highest_bit|T_E32X);
             //neg diff
             var_combos_vm_code.d_neg();
             var_combos_vm_code.pop(T_INVALID);
             //add count,1
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(1);
             var_combos_vm_code.b_add();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,count+1
             var_combos_vm_code.d_shl();
             var_combos_vm_code.pop(T_INVALID);
             //add diff,最高位
             var_combos_vm_code.push(highest_bit|T_E32X);
             var_combos_vm_code.d_add();
             var_combos_vm_code.pop(T_INVALID);
             //neg diff
             var_combos_vm_code.d_neg();
             var_combos_vm_code.pop(T_INVALID);
             //shl diff,7 - count_reg
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.b_push_imm(32-1);
             var_combos_vm_code.b_sub();
             var_combos_vm_code.pop(T_INVALID);

             var_combos_vm_code.d_shl();
             var_combos_vm_code.pop(T_INVALID);
             //shr dest_reg,count_reg
             var_combos_vm_code.push(dest_reg|T_E32X);
             var_combos_vm_code.push(count_reg|T_E32X|T_16X|T_8H);
             var_combos_vm_code.d_shr();
             var_combos_vm_code.popf();
             //add dest_reg,diff
             var_combos_vm_code.d_or();
             var_combos_vm_code.pop(T_INVALID);
             write_vm_operand(var_combos_vm_code,get_operand1(var_ud));

             break;
         default:
             break;
         }
         var_combos_vm_code.unlock_tmp_vmregister(count_reg);
         var_combos_vm_code.unlock_tmp_vmregister(dest_reg);
         var_combos_vm_code.unlock_tmp_vmregister(highest_bit);
         var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Iscasb: //edi - ~df + df
     {
       /*
        *
        * df = 1
        * neg df      ;0xffffffff
        * add edi,df
        * not df      ;0
        * sub edi,df
        *
        * df = 0
        * neg df      ;0
        * add edi,df
        * not df      ;0xffffffff
        * sub edi,df
        *
        */
       var_combos_vm_code.impact_vmregister(false);
       var_combos_vm_code.push(T_EDI);
       //var_combos_vm_code.push(T_FLAG);
       var_combos_vm_code.b_read_mem();
       var_combos_vm_code.push(T_AL);
       var_combos_vm_code.b_cmp();
       var_combos_vm_code.pop(T_FLAG);

       var_combos_vm_code.get_string_ins_diff();
       var_combos_vm_code.b_push_imm(0);
       var_combos_vm_code.d_shl();
       var_combos_vm_code.pop(T_INVALID);

       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);

       /*
       //sub 0,df
       int tmp_vmregister_df = var_combos_vm_code.get_tmp_vmregister();
       var_combos_vm_code.push(T_FLAG); //t_edi
       var_combos_vm_code.get_df();
       var_combos_vm_code.d_push_imm(0);
       var_combos_vm_code.d_sub();
       //var_combos_vm_code.int3();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.push_vsp();
       var_combos_vm_code.d_read_mem();
       var_combos_vm_code.pop(tmp_vmregister_df | T_E32X);

       //add edi,df
       int tmp_vmregister_edi = var_combos_vm_code.get_tmp_vmregister();
       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(tmp_vmregister_edi | T_E32X);

       //not df
       //var_combos_vm_code.push(T_FLAG);
       var_combos_vm_code.push(tmp_vmregister_df | T_E32X);
       //var_combos_vm_code.get_df();
       var_combos_vm_code.d_not();
       var_combos_vm_code.pop(T_INVALID);

       //sub edi,df
       var_combos_vm_code.push(tmp_vmregister_edi | T_E32X);
       var_combos_vm_code.d_sub();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);
       //var_combos_vm_code.int3(); //

       var_combos_vm_code.unlock_tmp_vmregister(tmp_vmregister_edi);
       var_combos_vm_code.unlock_tmp_vmregister(tmp_vmregister_df);
       //var_combos_vm_code.int3(); //sub edi,~df
      */
       var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Iscasw: //edi - ~df + df
     {
       var_combos_vm_code.impact_vmregister(false);
       var_combos_vm_code.push(T_EDI);
       //var_combos_vm_code.push(T_FLAG);
       var_combos_vm_code.w_read_mem();
       var_combos_vm_code.push(T_AX);
       var_combos_vm_code.w_cmp();
       var_combos_vm_code.pop(T_FLAG);

       var_combos_vm_code.get_string_ins_diff();
       var_combos_vm_code.b_push_imm(1);
       var_combos_vm_code.d_shl();
       var_combos_vm_code.pop(T_INVALID);

       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);

       //var_combos_vm_code.int3(); //sub edi,~df
       var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Iscasd: //edi - ~df + df
     {
       var_combos_vm_code.impact_vmregister(false);
       var_combos_vm_code.push(T_EDI);
       //var_combos_vm_code.push(T_FLAG);
       var_combos_vm_code.d_read_mem();
       var_combos_vm_code.push(T_EAX);
       var_combos_vm_code.d_cmp();
       var_combos_vm_code.pop(T_FLAG);


       var_combos_vm_code.get_string_ins_diff();
       var_combos_vm_code.b_push_imm(2);
       var_combos_vm_code.d_shl();
       var_combos_vm_code.pop(T_INVALID);

       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);
       var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Imovsb:
     {
       var_combos_vm_code.impact_vmregister(false);
       var_combos_vm_code.push(T_ESI);
       var_combos_vm_code.b_read_mem();
       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.b_write_mem();

       var_combos_vm_code.get_string_ins_diff();
       var_combos_vm_code.push_vsp();
       var_combos_vm_code.d_read_mem();
       //var_combos_vm_code.b_push_imm(0);
       //var_combos_vm_code.d_shl();
       //var_combos_vm_code.pop(T_INVALID);

       var_combos_vm_code.push(T_ESI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_ESI);

       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);
       var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Imovsd:
     {
       var_combos_vm_code.impact_vmregister(false);
       var_combos_vm_code.push(T_ESI);
       var_combos_vm_code.d_read_mem();
       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_write_mem();

       var_combos_vm_code.get_string_ins_diff();
       var_combos_vm_code.b_push_imm(2);
       var_combos_vm_code.d_shl();
       var_combos_vm_code.pop(T_INVALID);
       //var_combos_vm_code.int3();
       var_combos_vm_code.push_vsp();
       var_combos_vm_code.d_read_mem();


       var_combos_vm_code.push(T_ESI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_ESI);

       var_combos_vm_code.push(T_EDI);
       var_combos_vm_code.d_add();
       var_combos_vm_code.pop(T_INVALID);
       var_combos_vm_code.pop(T_EDI);
       var_combos_vm_code.impact_vmregister(true);
     }
     break;
    case UD_Ijnz: //ZF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);
     }/*}}}*/
     break;
    case UD_Ijz:  //ZF != 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);
     }/*}}}*/
     break;  
    case UD_Ija: //CF = 0 && ZF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x1);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.b_push_imm(2);
        var_combos_vm_code.d_shl();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.d_and();       //and zf 和 cf 
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijae:  // CF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(1);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(2);
        var_combos_vm_code.d_shl();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true); 
     }/*}}}*/
     break;
    case UD_Ijb://CF = 1
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        //var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(1);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(2);
        var_combos_vm_code.d_shl();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijbe: //CF = 1 || ZF = 1
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        //var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x1);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.b_push_imm(2);
        var_combos_vm_code.d_shl();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.d_or();       //or zf 和 cf 
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);   
     }/*}}}*/
     break;
    case UD_Ijcxz:  //CX = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        /*var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);*/
        var_combos_vm_code.w_push_imm(0);
        var_combos_vm_code.w_push_imm(0);
        //var_combos_vm_code.w_push_imm(0xffff);
        //var_combos_vm_code.w_and();
        //var_combos_vm_code.pop(T_INVALID);
        for (int i = 0 ; i < 16 ; i++)
        {   
           //var_combos_vm_code.push_vsp();
           //var_combos_vm_code.w_read_mem();   
           var_combos_vm_code.push(T_CX);
           var_combos_vm_code.w_push_imm(1 << i);
           var_combos_vm_code.w_and();
           var_combos_vm_code.pop(T_INVALID);
           var_combos_vm_code.b_push_imm(i);
           var_combos_vm_code.w_shr();
           var_combos_vm_code.pop(T_INVALID);
           var_combos_vm_code.w_or();
           var_combos_vm_code.pop(T_INVALID);
        }

        var_combos_vm_code.b_push_imm(14);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true); 
     }/*}}}*/
     break;
    case UD_Ijecxz: //ECX = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.d_push_imm(0);
        for (int i = 0 ; i < 32 ; i++)
        {   
           var_combos_vm_code.push(T_ECX);
           var_combos_vm_code.d_push_imm(1 << i);
           var_combos_vm_code.d_and();
           var_combos_vm_code.pop(T_INVALID);
           var_combos_vm_code.b_push_imm(i);
           var_combos_vm_code.d_shr();
           var_combos_vm_code.pop(T_INVALID);
           var_combos_vm_code.d_or();
           var_combos_vm_code.pop(T_INVALID);
        }

        var_combos_vm_code.b_push_imm(2);
        var_combos_vm_code.d_shl();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijg:  //ZF = 0 && SF = OF
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();         //get_sf
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();         //get_of
        var_combos_vm_code.pop(T_INVALID); 

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_xor();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(1);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_not();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true); 
     }/*}}}*/
     break;
    case UD_Ijge: //SF = OF
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();         //get_sf
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();         //get_of
        var_combos_vm_code.pop(T_INVALID); 

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_xor();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(1);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_not();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_push_imm(4);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijl:  // OF != SF
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR); 

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();         //get_sf
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();         //get_of
        var_combos_vm_code.pop(T_INVALID); 

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_xor();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(1);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_not();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_push_imm(4);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);   
     }/*}}}*/
     break;
    case UD_Ijle:  // ZF = 1 || SF != OF
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR); 

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x40);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);
        
        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();         //get_sf
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();         //get_of
        var_combos_vm_code.pop(T_INVALID); 

        var_combos_vm_code.b_push_imm(4);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_xor();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(1);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_not();
        var_combos_vm_code.pop(T_INVALID);

        //var_combos_vm_code.d_or();
        var_combos_vm_code.d_push_imm(4);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_or();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);    
     }/*}}}*/
     break;
    case UD_Ijno: // OF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(9);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true); 
     }/*}}}*/
     break;
    case UD_Ijnp: // PF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x4);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijns: // SF = 0
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(5);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijo:  // OF = 1
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        //var_combos_vm_code.push(T_NEXTINSADDR);
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR);

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x800);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(9);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);  
     }/*}}}*/
     break;
    case UD_Ijp:  // PF = 1
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR); 

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x4);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);   
     }/*}}}*/
     break;
    case UD_Ijs:  // SF = 1
     {/*{{{*/
        var_combos_vm_code.impact_vmregister(false);
        
        var_combos_vm_code.push(T_JMPINSADDR);
        var_combos_vm_code.push(T_NEXTINSADDR); 

        var_combos_vm_code.push_vsp();

        var_combos_vm_code.push(T_FLAG);
        var_combos_vm_code.d_push_imm(0x80);
        var_combos_vm_code.d_and();
        var_combos_vm_code.pop(T_INVALID);

        var_combos_vm_code.b_push_imm(5);
        var_combos_vm_code.d_shr();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_add();
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.d_read_mem();
        var_combos_vm_code.pop(T_NEXTINSADDR);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.pop(T_INVALID);
        var_combos_vm_code.impact_vmregister(true);   
     }/*}}}*/
     break;
   }
}/*}}}*/


void BuildVMByteCode::full_vmregister_store(std::vector<CodePiece> & var_list_code_piece,
      std::map<int,RegisterStore> & var_map_label_vmreg_store_in,
      std::map<int,RegisterStore> & var_map_label_vmreg_store_out)
{/*{{{*/
   size_t var_list_size = var_list_code_piece.size();
   for (size_t i = 0; i < var_list_size; i++)
   {
      set_vmregister_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,i);
   }
   //set_vmregister_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,0); 
   //printf("In size %d,Out size %d\n",var_map_label_vmreg_store_in.size(),var_map_label_vmreg_store_out.size());
   // set_vmregister_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,0x38); 
   //  set_vmregister_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,0x1);  

}/*}}}*/

void BuildVMByteCode::set_vmregister_store(std::vector<CodePiece> & var_list_code_piece,
      std::map<int,RegisterStore> & var_map_label_vmreg_store_in,
      std::map<int,RegisterStore> & var_map_label_vmreg_store_out, 
      int var_cur_label)
{/*{{{*/
    std::vector<CodePiece>::iterator iter = var_list_code_piece.begin();
    bool find_out = false;
    bool find_in = false;
    std::vector<int> var_label_in;
    std::vector<int> var_label_out;
    RegisterStore var_store_in;    
    RegisterStore var_store_out;
    for (iter;iter != var_list_code_piece.end();iter++)
    {
       //查找是否有指令跳转到这里
       if (iter->get_jmplabel() == var_cur_label)
       {
          if (var_map_label_vmreg_store_out.find(iter->get_label()) != var_map_label_vmreg_store_out.end()) 
          {
             if (var_store_in.get_key() != var_map_label_vmreg_store_out[iter->get_label()].get_key())
             {
                asm("int3");
             }
             var_store_in = var_map_label_vmreg_store_out[iter->get_label()];
             var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(var_cur_label,
                      var_map_label_vmreg_store_out[iter->get_label()]));
             find_in = true;
          }
          else
          {
             //if (iter->get_jmplabel_type() == TYPE_LABEL)
                var_label_out.push_back(iter->get_label());
          }
       }
       //查找上条指令
       if (iter->get_label() + 1 == var_cur_label && iter->get_jmplabel_type() == TYPE_LABEL)
       {
              if (var_store_in.get_key() != var_map_label_vmreg_store_out[iter->get_label()].get_key())
             {
                asm("int3");
             }                          
          if (var_map_label_vmreg_store_out.find(iter->get_label()) != var_map_label_vmreg_store_out.end())
          {
             var_store_in = var_map_label_vmreg_store_out[iter->get_label()]; 
             var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(var_cur_label,
                      var_map_label_vmreg_store_out[iter->get_label()]));
             find_in = true;
          } 
          else
          {
              //if (iter->get_jmplabel_type() == TYPE_LABEL) 
                 var_label_out.push_back(iter->get_label());
          }  
       }
       
       if (iter->get_label() == var_cur_label)
       {
               if (var_store_out.get_key() != var_map_label_vmreg_store_in[iter->get_label()].get_key())
             {
                asm("int3");
             }                 
          if (var_map_label_vmreg_store_in.find(iter->get_jmplabel()) != var_map_label_vmreg_store_in.end())
          {
             
                var_store_out = var_map_label_vmreg_store_in[iter->get_jmplabel()]; 
                var_map_label_vmreg_store_out.insert(std::make_pair<int,RegisterStore>(var_cur_label,
                         var_store_out));
                find_out = true;
          }
          else{
                if (iter->get_jmplabel_type() == TYPE_LABEL)
                  var_label_in.push_back(iter->get_jmplabel());
          }
       }
       //
       if (iter->get_label() - 1 == var_cur_label)
       {
             if (var_store_out.get_key() != var_map_label_vmreg_store_in[iter->get_label()].get_key())
             {
                asm("int3");
             }                                                            
          if (var_map_label_vmreg_store_in.find(iter->get_label()) != var_map_label_vmreg_store_in.end())
          {
             var_store_out = var_map_label_vmreg_store_in[iter->get_label()];
             var_map_label_vmreg_store_out.insert(std::make_pair<int,RegisterStore>(var_cur_label,
                      var_map_label_vmreg_store_in[iter->get_label()]));
             find_out = true;
          }
          else
          {
              //pe() == TYPE_LABEL)      
                 var_label_in.push_back(iter->get_label());
          }
       }
    }

    if (find_out == false)
    {
       VCombosVMCode var_t;
       
       var_t.upset_register_array(var_store_out);
       var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(var_cur_label,var_store_out));
    }
    for (std::vector<int>::iterator iter = var_label_out.begin();
          iter != var_label_out.end();iter++)
    {
         var_map_label_vmreg_store_out.insert(std::make_pair<int,RegisterStore>(*iter,var_store_out));
    }    

    if (find_in == false)
    {
       VCombosVMCode var_t;
       //RegisterStore var_store;
       var_t.upset_register_array(var_store_in);
       var_map_label_vmreg_store_out.insert(std::make_pair<int,RegisterStore>(var_cur_label,var_store_in)); 
    }
    for (std::vector<int>::iterator iter = var_label_in.begin();
          iter != var_label_in.end();iter++)
    {
         var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(*iter,var_store_in));
    }  
}/*}}}*/

void BuildVMByteCode::set_lastpiece_register_store(std::vector<CodePiece> &var_list_code_piece,
        std::map<int,RegisterStore> & var_map_label_vmreg_store)
{/*{{{*/
    VCombosVMCode var_t;
    RegisterStore var_store;
    var_t.upset_register_array(var_store);

    std::vector<CodePiece>::iterator iter = var_list_code_piece.begin();
    for (iter;iter != var_list_code_piece.end();iter++)
    {
        if ( iter->get_jmplabel_type() == TYPE_RET &&
                iter->get_is_jcc() == false)
        {
            printf("LastPieceLabel:%d\n",iter->get_label());
              var_map_label_vmreg_store.insert( std::make_pair<int,RegisterStore>(
                          iter->get_label(),
                          var_store));
        }
    }
}/*}}}*/
void BuildVMByteCode::full_register_store(std::vector<CodePiece> &var_list_code_piece,
        std::map<int,RegisterStore> & var_map_label_vmreg_store_in,
        std::map<int,RegisterStore> & var_map_label_vmreg_store_out
        )   
{/*{{{*/
    std::map<int,RegisterStore> store;
    set_lastpiece_register_store(var_list_code_piece,store);
    set_register_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,store);

    
    int code_piece_count = var_list_code_piece.size();
    int n = code_piece_count;
    
    while (n)
    {
        VCombosVMCode combs;
        RegisterStore regstore;
        combs.upset_register_array(regstore);
        bool b  = var_map_label_vmreg_store_in.find(var_list_code_piece[--n].get_label()) == 
            var_map_label_vmreg_store_in.end();
        if (b)
        {
            store.insert(std::make_pair<int,RegisterStore>(var_list_code_piece[n].get_label(),regstore)); 
            set_register_store(var_list_code_piece,var_map_label_vmreg_store_in,var_map_label_vmreg_store_out,store);
        }
    } 
    if (var_map_label_vmreg_store_in.find(var_list_code_piece[0].get_label()) == 
      var_map_label_vmreg_store_in.end()) {
     VCombosVMCode combs;
     RegisterStore regstore;
     combs.upset_register_array(regstore);
     var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(
        var_list_code_piece[0].get_label(),
        regstore
        ));
    }
}/*}}}*/

void BuildVMByteCode::set_register_store(std::vector<CodePiece> &var_list_code_piece,
        std::map<int,RegisterStore> & var_map_label_vmreg_store_in,
        std::map<int,RegisterStore> & var_map_label_vmreg_store_out,
        std::map<int,RegisterStore> & var_map_lastpiece_vmreg_store)  
{/*{{{*/
    std::map<int,RegisterStore>::iterator lastpiece_iter =  var_map_lastpiece_vmreg_store.begin();
    std::map<int,RegisterStore>::iterator  store_in_iter = var_map_label_vmreg_store_in.begin();
    std::map<int,RegisterStore>::iterator store_out_iter = var_map_label_vmreg_store_out.begin(); 
    
    //printf_map_register_store(var_map_lastpiece_vmreg_store,"var_map_lastpiece_vmreg_store");
    int i = 0;
    // printf("var_map_lastpiece_vmreg_store大小:%d\n",var_map_lastpiece_vmreg_store.size());     
    //for (lastpiece_iter; lastpiece_iter != var_map_lastpiece_vmreg_store.end();)//lastpiece_iter++)
    while (!var_map_lastpiece_vmreg_store.empty())
    {
        printf("第%d次进入循环,var_map_lastpiece_vmreg_store大小:%d\n",i++,var_map_lastpiece_vmreg_store.size());
        std::map<int,RegisterStore>::iterator var_iter_map_t = lastpiece_iter;
        std::vector<CodePiece>::iterator codepiece_iter = var_list_code_piece.begin(); 
        /*if (i > 100)
        {
           break;
        } */
        for (codepiece_iter; codepiece_iter != var_list_code_piece.end(); codepiece_iter++)
        {
            if (lastpiece_iter->first == codepiece_iter->get_jmplabel() || 
                 (lastpiece_iter->first == (codepiece_iter->get_label() + 1 )) //&&
                  //codepiece_iter->get_jmplabel_type() != TYPE_MEM) 
                 ) {
                var_map_label_vmreg_store_out.insert(std::make_pair<int,RegisterStore>(
                            codepiece_iter->get_label(),
                            lastpiece_iter->second
                            ));
                var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(
                            codepiece_iter->get_label() + 1,
                            lastpiece_iter->second
                            ));
                if (var_map_label_vmreg_store_in.find(codepiece_iter->get_label()) !=
                        var_map_label_vmreg_store_in.end())
                {
                  
                   if (codepiece_iter->get_label() != codepiece_iter->get_jmplabel())
                      var_map_lastpiece_vmreg_store.insert(std::make_pair<int,RegisterStore>(
                            codepiece_iter->get_label() + 1,
                            lastpiece_iter->second
                            )); 
               //printf("aaaaaaaaaaaa %s,%x,%x\n" ,var_list_code_piece[codepiece_iter->get_label() + 1 ]
               //                    .get_piece().back().insn_buffer,codepiece_iter->get_label(),codepiece_iter->get_jmplabel());    
                }
                std::map<int,RegisterStore> var_out;
                std::vector<CodePiece> var_t_CodePiece;
                for (std::vector<CodePiece>::iterator iter_t_codepiece = var_list_code_piece.begin();
                        iter_t_codepiece!= var_list_code_piece.end();iter_t_codepiece++)
                {
                    if (var_map_label_vmreg_store_out.find(iter_t_codepiece->get_label()) != 
                            var_map_label_vmreg_store_out.end())
                    {
                        bool b1 =  (var_map_lastpiece_vmreg_store.find(iter_t_codepiece->get_jmplabel()) ==
                                 var_map_lastpiece_vmreg_store.end());
                        bool b2 = (var_map_label_vmreg_store_in.find(iter_t_codepiece->get_jmplabel()) ==
                                 var_map_label_vmreg_store_in.end()); 
                        bool b3 = iter_t_codepiece->get_jmplabel_type() == TYPE_LABEL;
                         if (b1 && b2 && b3)
                         {
                             //printf("标签是:%d\n",iter_t_codepiece->get_jmplabel());
                             //if (var_map_label_vmreg_store_in.find(iter_t_codepiece->get_jmplabel()) == 
                             //      var_map_label_vmreg_store_in.end())
                             {

                             
                             var_map_lastpiece_vmreg_store.insert(std::make_pair<int,RegisterStore>(
                                         iter_t_codepiece->get_jmplabel(),
                                         lastpiece_iter->second 
                                      ));
               
                             }
                             var_map_label_vmreg_store_in.insert(std::make_pair<int,RegisterStore>(
                                         iter_t_codepiece->get_jmplabel(),
                                         lastpiece_iter->second
                                         ));

                                                             
                         } //else if (var_map_label_vmreg_store_out.find(iter_t_codepiece-))
                    }
                }    
                //var_iter_map_t = lastpiece_iter;
                                               
            }
            
            
        }
        
        
        var_map_lastpiece_vmreg_store.erase(lastpiece_iter);
        lastpiece_iter = var_map_lastpiece_vmreg_store.begin();

        /*set_register_store(var_list_code_piece,
                    var_map_label_vmreg_store_in,
                    var_map_label_vmreg_store_out,
                    var_map_t);   */
             
    }
    
}/*}}}*/

/*
void BuildVMByteCode::full_label_vmkey(std::vector<CodePiece> &var_list_code_piece,
      std::map<int,long> & var_map_label_vmkey,
      int var_cur_label,
      int var_key       //代表的是进入时候的key
      )
{
   long firstkey = m_random() ;
   for (std::vector<CodePiece>::iterator xiter = var_list_code_piece.begin();
         xiter != var_list_code_piece.end();xiter++)
   {
      if (xiter->get_is_jcc())
      {
         for (std::vector<CodePiece>::iterator yiter = var_list_code_piece.begin();
            yiter != var_list_code_piece.end();yiter++)
         {
            if (yiter->get_jmplabel() == xiter->get_label())
            {
            var_map_label_vmkey.insert(std:: )
            }
         }  
      }

      var_map_label_vmkey.insert()
   }
} */
