import idaapi
import idc
from unicorn import *
from unicorn.arm64_const import *
from keystone import *

BASE_reg=0x81
class txxxxk:
    def __init__(self,address,size) -> None:
        self.start_addre=address
        self.size=size
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mu.mem_map(address&0xfff000,0x20000000)
        data = idaapi.get_bytes(address,size)
        self.mu.mem_write(address,data) 
        self.mu.reg_write(UC_ARM64_REG_SP,0x11000000) 
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.cmp_reg_num=0
        self.no_nop=[]
        self.br_remake=[]
        self.br_reg=[]
        self.b_addr1=0
        self.b_addr2=0
        self.cmp_seg=""
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        
    def hook_code(self,mu, address, size, user_data):
        print("%x"%address)
        insn=idaapi.insn_t() 
        idaapi.decode_insn(insn,address)
        dism=idc.generate_disasm_line(address,0)
        if insn.itype==idaapi.ARM_cmp:
            self.cmp_reg_num=insn.Op1.reg-BASE_reg
            self.no_nop.append(address)
        if insn.itype == idaapi.ARM_csel:
            self.b_addr1=self.mu.reg_read(UC_ARM64_REG_X0+insn.Op2.reg-BASE_reg)
            print(insn.Op3.reg-BASE_reg)
            self.b_addr2=self.mu.reg_read(UC_ARM64_REG_X0+insn.Op3.reg-BASE_reg)
            self.br_reg.append(insn.Op2.reg-BASE_reg)
            self.br_reg.append(insn.Op3.reg-BASE_reg)
            print("跳转地址 %x"%self.b_addr1)
            print("跳转地址 %x"%self.b_addr2)
            self.br_remake.append(address)
            self.no_nop.append(address)
            self.cmp_seg=dism.split(",")[-1].split(" ")[-1]
        if insn.itype==idaapi.ARM_br:
            self.br_remake.append(address)
            self.no_nop.append(address)

    def start(self):
        try: 
            self.mu.emu_start(self.start_addre,self.start_addre+self.size)
        except UcError as e:
            if e.errno==UC_ERR_EXCEPTION:
                print("go on")
            else:
                print(e)
                print("ESP = %x" %self.mu.reg_read(UC_ARM64_REG_SP))
                return
        self.check_reg()
        print("no_nop list ")
        print(self.no_nop)
        print("br_reg list ")
        print(self.br_reg)
        print("br list")
        print(self.br_remake)
        self.nop()
        self.change_ida_byte()

    def check_reg(self):
        i=self.size
        nop_list=[]
        while(i>=0):
            insn=idaapi.insn_t() 
            idaapi.decode_insn(insn,self.start_addre+i)

            flag=False
            for op in insn.ops:
                if op.reg!=0 and (op.reg-BASE_reg) in self.br_reg:
                    flag=True
            for op in insn.ops:
                if flag:
                    if op.reg!=0 and (op.reg-BASE_reg) not in self.br_reg and op.reg!=0xa1:
                        self.br_reg.append(op.reg-BASE_reg)
                    print("%x 参与计算的其他寄存器 %d"%(self.start_addre+i,op.reg-BASE_reg))
                    nop_list.append(self.start_addre+i)
            i-=4
        for no_nop_i in self.no_nop:
            if no_nop_i in nop_list:
                nop_list.remove(no_nop_i)
        j=0
        while(j<self.size):
            if j+self.start_addre not in nop_list:
                self.no_nop.append(self.start_addre+j)
            j+=4

    
    def nop(self):
        i=0
        while(i<self.size):
            if i+self.start_addre in self.no_nop:
                i+=4
                continue
            idaapi.patch_dword(i+self.start_addre,0xD503201F)
            i+=4

    def change_ida_byte(self):
        code="B"+self.cmp_seg+" "+hex(self.b_addr1)
        print(code,self.br_remake[0])
        encoding, count = self.ks.asm(code,self.br_remake[0])
        i=0
        print(code)
        for cc in encoding:
            idaapi.patch_byte(self.br_remake[0]+i,cc)
            i+=1
        code="B"+" "+hex(self.b_addr2)
        encoding, count = self.ks.asm(code,self.br_remake[1])
        print(code)
        i=0
        for cc in encoding:
            idaapi.patch_byte(self.br_remake[1]+i,cc)
            i+=1     