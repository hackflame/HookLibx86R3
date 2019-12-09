#include "stdafx.h"
#include "disasm.h"


#define PSEUDOOP       128

#define WW             0x01
#define SS             0x02
#define WS             0x03
#define W3             0x08
#define CC             0x10
#define FF             0x20
#define LL             0x40
#define PR             0x80
#define WP             0x81

#define NNN            0
#define REG            1
#define RCM            2
#define RG4            3
#define RAC            4
#define RAX            5
#define RDX            6
#define RCL            7
#define RS0            8
#define RST            9
#define RMX            10
#define R3D            11
#define MRG            12
#define MR1            13
#define MR2            14
#define MR4            15
#define RR4            16
#define MR8            17
#define RR8            18
#define MRD            19
#define RRD            20
#define MRJ            21
#define MMA            22
#define MML            23
#define MMS            24
#define MM6            25
#define MMB            26
#define MD2            27
#define MB2            28
#define MD4            29
#define MD8            30
#define MDA            31
#define MF4            32
#define MF8            33
#define MFA            34
#define MFE            35
#define MFS            36
#define MFX            37
#define MSO            38
#define MDE            39
#define MXL            40
#define IMM            41
#define IMU            42
#define VXD            43
#define IMX            44
#define C01            45
#define IMS            46
#define IM1            47
#define IM2            48
#define IMA            49
#define JOB            50
#define JOW            51
#define JMF            52
#define SGM            53
#define SCM            54
#define CRX            55
#define DRX            56

#define PRN            (PSEUDOOP+0)
#define PRF            (PSEUDOOP+1)
#define PAC            (PSEUDOOP+2)
#define PAH            (PSEUDOOP+3)
#define PFL            (PSEUDOOP+4)
#define PS0            (PSEUDOOP+5)
#define PS1            (PSEUDOOP+6)
#define PCX            (PSEUDOOP+7)
#define PDI            (PSEUDOOP+8)

#define DAE_NOERR      0               // No error
#define DAE_BADCMD     1               // 无法识别指令
#define DAE_CROSS      2               // 内存块越界
#define DAE_BADSEG     3               // 无法识别的寄存器
#define DAE_MEMORY     4               // Register where only memory allowed
#define DAE_REGISTER   5               // Memory where only register allowed
#define DAE_INTERN     6               // Internal error

#define REG_EAX        0   
#define REG_ECX        1          
#define REG_EDX        2
#define REG_EBX        3
#define REG_ESP        4
#define REG_EBP        5
#define REG_ESI        6
#define REG_EDI        7

#define SEG_UNDEF     -1
#define SEG_ES         0    
#define SEG_CS         1
#define SEG_SS         2
#define SEG_DS         3
#define SEG_FS         4
#define SEG_GS         5

// Warnings
#define DAW_SEGMENT    0x0002
#define DAW_PRIV       0x0004
#define DAW_IO         0x0008
#define DAW_LOCK       0x0040
#define DAW_STACK      0x0080

//自定义
#define   C_CMD    0x00
#define   C_NOP    0x90

#define   C_TST    0x01		//比较
#define   C_CMP    0x02
#define   C_CMPS   0x03
#define   C_CMPSB  0X04
#define   C_CMPSW  0X05
#define   C_CMPSD  0X06

#define   C_MOV    0x11
#define   C_MOVS   0x12
#define	  C_MOVSX  0x13
#define   C_MOVSB  0x14
#define   C_MOVSW  0x15
#define   C_MOVSD  0x16
#define   C_MOVZX  0x17


#define   C_JMP    0x21		//转向
#define   C_JMC    0x22
#define   C_CAL    0x23
#define   C_RET    0x24

#define   C_XOR    0x31		//位操作
#define   C_AND    0x32
#define   C_OR     0x33
#define   C_NOT    0x34


#define   C_PSH    0x41		//进出栈操作
#define   C_POP    0x42
#define   C_PSHA   0x43
#define   C_POPA   0x44
#define   C_PSHF   0x45
#define   C_POPF   0x46

#define   C_ADD    0x51		//算术计算
#define   C_ADC    0x52
#define   C_SBB    0x53
#define   C_SUB    0x54
#define   C_INC    0x55
#define   C_DEC    0x56
#define   C_MUL    0x57
#define   C_IMUL   0x58
#define   C_DIV    0x59
#define   C_IDIV   0x5A

#define   C_NEG    0x61		//取反
#define   C_LEA    0x62		//取址
#define   C_XCHG   0x63

#define   C_SHR    0x71		//位移
#define   C_SHL    0x72
#define   C_ROL    0x73
#define   C_ROR    0x74
#define   C_RCL    0x75
#define   C_RCR    0x76
#define   C_SAR    0x77
#define   C_SAL    0x78

#define   C_CLI    0x81		//特殊指令
#define   C_STI    0x82
#define   C_ENTER  0x83
#define   C_LEAVE  0x84
#define   C_INT    0x85
#define   C_INT3   0x86
#define   C_SYSENTER    0x87
#define   C_SYSEXIT     0x88

#define	  C_SETNE  0xA1



#define   C_MMX    0xF1		//占位
#define   C_FLT    0xF2
#define   C_FLG    0xF3
#define   C_RTF    0xF4
#define   C_REP    0xF5
#define   C_DAT    0xF6
#define   C_EXPL   0xF7
#define   C_SIZEMASK 0xF8

#define   C_NOW    0xF9    //3d now
#define   C_PRI    0xFA    //特权指令     <HLT>

#define   C_RARE   0xFB    //罕见指令
#define   C_BAD    0xFC    //未识别指令

typedef struct _CmdData {
	ULONG          mask;
	ULONG          code;
	UCHAR          len;
	UCHAR          bits;
	UCHAR          arg1, arg2, arg3;
	UCHAR          type;
}CmdData, *PCmdData;


const CmdData CmdDataTable[] = {
	{ 0x0000FF, 0x000090, 1, 00, NNN, NNN, NNN, C_NOP },  //'NOP'),
	{ 0x0000FE, 0x00008A, 1, WW, REG, MRG, NNN, C_MOV },  //'MOV'),
	{ 0x0000F8, 0x000050, 1, 00, RCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FE, 0x000088, 1, WW, MRG, REG, NNN, C_MOV },  //'MOV'),
	{ 0x0000FF, 0x0000E8, 1, 00, JOW, NNN, NNN, C_CAL },  //'CALL'),
	{ 0x0000FD, 0x000068, 1, SS, IMM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FF, 0x00008D, 1, 00, REG, MMA, NNN, C_LEA },  //'LEA'),
	{ 0x0000FF, 0x000074, 1, CC, JOB, NNN, NNN, C_JMC },  //'JE,JZ'),
	{ 0x0000F8, 0x000058, 1, 00, RCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x0038FC, 0x000080, 1, WS, MRG, IMM, NNN, C_ADD },  //'ADD'),
	{ 0x0000FF, 0x000075, 1, CC, JOB, NNN, NNN, C_JMC },  //'JNZ,JNE'),
	{ 0x0000FF, 0x0000EB, 1, 00, JOB, NNN, NNN, C_JMP },  //'JMP'),
	{ 0x0000FF, 0x0000E9, 1, 00, JOW, NNN, NNN, C_JMP },  //'JMP'),
	{ 0x0000FE, 0x000084, 1, WW, MRG, REG, NNN, C_TST },  //'TEST'),
	{ 0x0038FE, 0x0000C6, 1, WW, MRG, IMM, NNN, C_MOV },  //'MOV'),
	{ 0x0000FE, 0x000032, 1, WW, REG, MRG, NNN, C_XOR },  //'XOR'),
	{ 0x0000FE, 0x00003A, 1, WW, REG, MRG, NNN, C_CMP },  //'CMP'),
	{ 0x0038FC, 0x003880, 1, WS, MRG, IMM, NNN, C_CMP },  //'CMP'),
	{ 0x0038FF, 0x0010FF, 1, 00, MRJ, NNN, NNN, C_CAL },  //'CALL'),
	{ 0x0000FF, 0x0000C3, 1, 00, PRN, NNN, NNN, C_RET },  //'RETN,RET'),
	{ 0x0000F0, 0x0000B0, 1, W3, RCM, IMM, NNN, C_MOV },  //'MOV'),
	{ 0x0000FE, 0x0000A0, 1, WW, RAC, IMA, NNN, C_MOV },  //'MOV'),
	{ 0x00FFFF, 0x00840F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JE,JZ'),
	{ 0x0000F8, 0x000040, 1, 00, RCM, NNN, NNN, C_INC },  //'INC'),
	{ 0x0038FE, 0x0000F6, 1, WW, MRG, IMU, NNN, C_TST },  //'TEST'),
	{ 0x0000FE, 0x0000A2, 1, WW, IMA, RAC, NNN, C_MOV },  //'MOV'),
	{ 0x0000FE, 0x00002A, 1, WW, REG, MRG, NNN, C_SUB },  //'SUB'),
	{ 0x0000FF, 0x00007E, 1, CC, JOB, NNN, NNN, C_JMC },  //'JLE,JNG'),
	{ 0x00FFFF, 0x00850F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JNZ,JNE'),
	{ 0x0000FF, 0x0000C2, 1, 00, IM2, PRN, NNN, C_RET },  //'RETN'),
	{ 0x0038FF, 0x0030FF, 1, 00, MRG, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0038FC, 0x000880, 1, WS, MRG, IMU, NNN, C_OR },   //'OR'),
	{ 0x0038FC, 0x002880, 1, WS, MRG, IMM, NNN, C_SUB },  //'SUB'),
	{ 0x0000F8, 0x000048, 1, 00, RCM, NNN, NNN, C_DEC },  //'DEC'),
	{ 0x00FFFF, 0x00BF0F, 2, 00, REG, MR2, NNN, C_MOVSX },  //'MOVSX'),
	{ 0x0000FF, 0x00007C, 1, CC, JOB, NNN, NNN, C_JMC },  //'JL,JNGE'),
	{ 0x0000FE, 0x000002, 1, WW, REG, MRG, NNN, C_ADD },  //'ADD'),
	{ 0x0038FC, 0x002080, 1, WS, MRG, IMU, NNN, C_AND },  //'AND'),
	{ 0x0000FE, 0x00003C, 1, WW, RAC, IMM, NNN, C_CMP },  //'CMP'),
	{ 0x0038FF, 0x0020FF, 1, 00, MRJ, NNN, NNN, C_JMP },  //'JMP'),
	{ 0x0038FE, 0x0010F6, 1, WW, MRG, NNN, NNN, C_NOT },  //'NOT'),
	{ 0x0038FE, 0x0028C0, 1, WW, MRG, IMS, NNN, C_SHR },  //'SHR'),
	{ 0x0000FE, 0x000038, 1, WW, MRG, REG, NNN, C_CMP },  //'CMP'),
	{ 0x0000FF, 0x00007D, 1, CC, JOB, NNN, NNN, C_JMC },  //'JGE,JNL'),
	{ 0x0000FF, 0x00007F, 1, CC, JOB, NNN, NNN, C_JMC },  //'JG,JNLE'),
	{ 0x0038FE, 0x0020C0, 1, WW, MRG, IMS, NNN, C_SHL },  //'SHL'),
	{ 0x0000FE, 0x00001A, 1, WW, REG, MRG, NNN, C_SBB },  //'SBB'),
	{ 0x0038FE, 0x0018F6, 1, WW, MRG, NNN, NNN, C_NEG },  //'NEG'),
	{ 0x0000FF, 0x0000C9, 1, 00, NNN, NNN, NNN, C_LEAVE },  //'LEAVE'),
	{ 0x0000FF, 0x000060, 1, 00, NNN, NNN, NNN, C_PSHA },  //'&PUSHA*'),
	{ 0x0038FF, 0x00008F, 1, 00, MRG, NNN, NNN, C_POP },  //'POP'),
	{ 0x0000FF, 0x000061, 1, 00, NNN, NNN, NNN, C_POPA },  //'&POPA*'),
	{ 0x0000F8, 0x000090, 1, 00, RAC, RCM, NNN, C_XCHG },  //'XCHG'),
	{ 0x0000FE, 0x000086, 1, WW, MRG, REG, NNN, C_XCHG },  //'XCHG'),
	{ 0x0000FE, 0x000000, 1, WW, MRG, REG, NNN, C_ADD },  //'ADD'),
	{ 0x0000FE, 0x000010, 1, WW, MRG, REG, NNN, C_ADC },  //'ADC'),
	{ 0x0000FE, 0x000012, 1, WW, REG, MRG, NNN, C_ADC },  //'ADC'),
	{ 0x0000FE, 0x000020, 1, WW, MRG, REG, NNN, C_AND },  //'AND'),
	{ 0x0000FE, 0x000022, 1, WW, REG, MRG, NNN, C_AND },  //'AND'),
	{ 0x0000FE, 0x000008, 1, WW, MRG, REG, NNN, C_OR },   //'OR'),
	{ 0x0000FE, 0x00000A, 1, WW, REG, MRG, NNN, C_OR },   //'OR'),
	{ 0x0000FE, 0x000028, 1, WW, MRG, REG, NNN, C_SUB },  //'SUB'),
	{ 0x0000FE, 0x000018, 1, WW, MRG, REG, NNN, C_SBB },  //'SBB'),
	{ 0x0000FE, 0x000030, 1, WW, MRG, REG, NNN, C_XOR },  //'XOR'),
	{ 0x0038FC, 0x001080, 1, WS, MRG, IMM, NNN, C_ADC },  //'ADC'),
	{ 0x0038FC, 0x001880, 1, WS, MRG, IMM, NNN, C_SBB },  //'SBB'),
	{ 0x0038FC, 0x003080, 1, WS, MRG, IMU, NNN, C_XOR },  //'XOR'),
	{ 0x0000FE, 0x000004, 1, WW, RAC, IMM, NNN, C_ADD },  //'ADD'),
	{ 0x0000FE, 0x000014, 1, WW, RAC, IMM, NNN, C_ADC },  //'ADC'),
	{ 0x0000FE, 0x000024, 1, WW, RAC, IMU, NNN, C_AND },  //'AND'),
	{ 0x0000FE, 0x00000C, 1, WW, RAC, IMU, NNN, C_OR },   //'OR'),
	{ 0x0000FE, 0x00002C, 1, WW, RAC, IMM, NNN, C_SUB },  //'SUB'),
	{ 0x0000FE, 0x00001C, 1, WW, RAC, IMM, NNN, C_SBB },  //'SBB'),
	{ 0x0000FE, 0x000034, 1, WW, RAC, IMU, NNN, C_XOR },  //'XOR'),
	{ 0x0038FE, 0x0000FE, 1, WW, MRG, NNN, NNN, C_INC },  //'INC'),
	{ 0x0038FE, 0x0008FE, 1, WW, MRG, NNN, NNN, C_DEC },  //'DEC'),
	{ 0x0000FE, 0x0000A8, 1, WW, RAC, IMU, NNN, C_TST },  //'TEST'),
	{ 0x0038FE, 0x0020F6, 1, WW, MRG, NNN, NNN, C_MUL },  //'MUL'),
	{ 0x0038FE, 0x0028F6, 1, WW, MRG, NNN, NNN, C_IMUL },  //'IMUL'),
	{ 0x00FFFF, 0x00AF0F, 2, 00, REG, MRG, NNN, C_IMUL },  //'IMUL'),
	{ 0x0000FF, 0x00006B, 1, 00, REG, MRG, IMX, C_IMUL },  //'IMUL'),
	{ 0x0000FF, 0x000069, 1, 00, REG, MRG, IMM, C_IMUL },  //'IMUL'),
	{ 0x0038FE, 0x0030F6, 1, WW, MRG, NNN, NNN, C_DIV },  //'DIV'),
	{ 0x0038FE, 0x0038F6, 1, WW, MRG, NNN, NNN, C_IDIV },  //'IDIV'),

	{ 0x0000FF, 0x000098, 1, 00, NNN, NNN, NNN, C_CMD },  //'&CBW:CWDE'),
	{ 0x0000FF, 0x000099, 1, 00, NNN, NNN, NNN, C_CMD },  //'&CWD:CDQ'),
	{ 0x0038FE, 0x0000D0, 1, WW, MRG, C01, NNN, C_ROL },  //'ROL'),
	{ 0x0038FE, 0x0008D0, 1, WW, MRG, C01, NNN, C_ROR },  //'ROR'),
	{ 0x0038FE, 0x0010D0, 1, WW, MRG, C01, NNN, C_RCL },  //'RCL'),
	{ 0x0038FE, 0x0018D0, 1, WW, MRG, C01, NNN, C_RCR },  //'RCR'),
	{ 0x0038FE, 0x0020D0, 1, WW, MRG, C01, NNN, C_SHL },  //'SHL'),
	{ 0x0038FE, 0x0028D0, 1, WW, MRG, C01, NNN, C_SHR },  //'SHR'),
	{ 0x0038FE, 0x0038D0, 1, WW, MRG, C01, NNN, C_SAR },  //'SAR'),
	{ 0x0038FE, 0x0000D2, 1, WW, MRG, RCL, NNN, C_ROL },  //'ROL'),
	{ 0x0038FE, 0x0008D2, 1, WW, MRG, RCL, NNN, C_ROR },  //'ROR'),
	{ 0x0038FE, 0x0010D2, 1, WW, MRG, RCL, NNN, C_RCL },  //'RCL'),
	{ 0x0038FE, 0x0018D2, 1, WW, MRG, RCL, NNN, C_RCR },  //'RCR'),
	{ 0x0038FE, 0x0020D2, 1, WW, MRG, RCL, NNN, C_SHL },  //'SHL'),
	{ 0x0038FE, 0x0028D2, 1, WW, MRG, RCL, NNN, C_SHR },  //'SHR'),
	{ 0x0038FE, 0x0038D2, 1, WW, MRG, RCL, NNN, C_SAR },  //'SAR'),
	{ 0x0038FE, 0x0000C0, 1, WW, MRG, IMS, NNN, C_ROL },  //'ROL'),
	{ 0x0038FE, 0x0008C0, 1, WW, MRG, IMS, NNN, C_ROR },  //'ROR'),
	{ 0x0038FE, 0x0010C0, 1, WW, MRG, IMS, NNN, C_RCL },  //'RCL'),
	{ 0x0038FE, 0x0018C0, 1, WW, MRG, IMS, NNN, C_RCR },  //'RCR'),
	{ 0x0038FE, 0x0038C0, 1, WW, MRG, IMS, NNN, C_SAR },  //'SAR'),

	{ 0x0000FF, 0x000070, 1, CC, JOB, NNN, NNN, C_JMC },  //'JO'),
	{ 0x0000FF, 0x000071, 1, CC, JOB, NNN, NNN, C_JMC },  //'JNO'),
	{ 0x0000FF, 0x000072, 1, CC, JOB, NNN, NNN, C_JMC },  //'JB,JC'),
	{ 0x0000FF, 0x000073, 1, CC, JOB, NNN, NNN, C_JMC },  //'JNB,JNC'),
	{ 0x0000FF, 0x000076, 1, CC, JOB, NNN, NNN, C_JMC },  //'JBE,JNA'),
	{ 0x0000FF, 0x000077, 1, CC, JOB, NNN, NNN, C_JMC },  //'JA,JNBE'),
	{ 0x0000FF, 0x000078, 1, CC, JOB, NNN, NNN, C_JMC },  //'JS'),
	{ 0x0000FF, 0x000079, 1, CC, JOB, NNN, NNN, C_JMC },  //'JNS'),
	{ 0x0000FF, 0x00007A, 1, CC, JOB, NNN, NNN, C_JMC },  //'JPE,JP'),
	{ 0x0000FF, 0x00007B, 1, CC, JOB, NNN, NNN, C_JMC },  //'JPO,JNP'),
	{ 0x0000FF, 0x0000E3, 1, 00, JOB, NNN, NNN, C_JMC },  //'$JCXZ:JECXZ'),
	{ 0x00FFFF, 0x00800F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JO'),
	{ 0x00FFFF, 0x00810F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JNO'),
	{ 0x00FFFF, 0x00820F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JB,JC'),
	{ 0x00FFFF, 0x00830F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JNB,JNC'),
	{ 0x00FFFF, 0x00860F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JBE,JNA'),
	{ 0x00FFFF, 0x00870F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JA,JNBE'),
	{ 0x00FFFF, 0x00880F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JS'),
	{ 0x00FFFF, 0x00890F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JNS'),
	{ 0x00FFFF, 0x008A0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JPE,JP'),
	{ 0x00FFFF, 0x008B0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JPO,JNP'),
	{ 0x00FFFF, 0x008C0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JL,JNGE'),
	{ 0x00FFFF, 0x008D0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JGE,JNL'),
	{ 0x00FFFF, 0x008E0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JLE,JNG'),
	{ 0x00FFFF, 0x008F0F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JG,JNLE'),

	{ 0x0000FF, 0x0000F8, 1, 00, NNN, NNN, NNN, C_CMD },  //'CLC'),
	{ 0x0000FF, 0x0000F9, 1, 00, NNN, NNN, NNN, C_CMD },  //'STC'),
	{ 0x0000FF, 0x0000F5, 1, 00, NNN, NNN, NNN, C_CMD },  //'CMC'),
	{ 0x0000FF, 0x0000FC, 1, 00, NNN, NNN, NNN, C_CMD },  //'CLD'),
	{ 0x0000FF, 0x0000FD, 1, 00, NNN, NNN, NNN, C_CMD },  //'STD'),
	{ 0x0000FF, 0x0000FA, 1, 00, NNN, NNN, NNN, C_CLI },  //'CLI'),
	{ 0x0000FF, 0x0000FB, 1, 00, NNN, NNN, NNN, C_STI },  //'STI'),
	{ 0x0000FF, 0x00008C, 1, FF, MRG, SGM, NNN, C_MOV },  //'MOV'),
	{ 0x0000FF, 0x00008E, 1, FF, SGM, MRG, NNN, C_MOV },  //'MOV'),
	{ 0x0000FE, 0x0000A6, 1, WW, MSO, MDE, NNN, C_CMPS },  //'CMPS'),
	{ 0x0000FE, 0x0000AC, 1, WW, MSO, NNN, NNN, C_CMD },  //'LODS'),
	{ 0x0000FE, 0x0000A4, 1, WW, MDE, MSO, NNN, C_MOVS },  //'MOVS'),
	{ 0x0000FE, 0x0000AE, 1, WW, MDE, PAC, NNN, C_CMD },  //'SCAS'),
	{ 0x0000FE, 0x0000AA, 1, WW, MDE, PAC, NNN, C_CMD },  //'STOS'),
	{ 0x00FEFF, 0x00A4F3, 1, WW, MDE, MSO, PCX, C_REP },  //'REP MOVS'),
	{ 0x00FEFF, 0x00ACF3, 1, WW, MSO, PAC, PCX, C_REP },  //'REP LODS'),
	{ 0x00FEFF, 0x00AAF3, 1, WW, MDE, PAC, PCX, C_REP },  //'REP STOS'),
	{ 0x00FEFF, 0x00A6F3, 1, WW, MDE, MSO, PCX, C_REP },  //'REPE CMPS'),
	{ 0x00FEFF, 0x00AEF3, 1, WW, MDE, PAC, PCX, C_REP },  //'REPE SCAS'),
	{ 0x00FEFF, 0x00A6F2, 1, WW, MDE, MSO, PCX, C_REP },  //'REPNE CMPS'),
	{ 0x00FEFF, 0x00AEF2, 1, WW, MDE, PAC, PCX, C_REP },  //'REPNE SCAS'),
	{ 0x0000FF, 0x0000EA, 1, 00, JMF, NNN, NNN, C_JMP },  //'JMP'),
	{ 0x0038FF, 0x0028FF, 1, 00, MMS, NNN, NNN, C_JMP },  //'JMP'),
	{ 0x0000FF, 0x00009A, 1, 00, JMF, NNN, NNN, C_CAL },  //'CALL'),
	{ 0x0038FF, 0x0018FF, 1, 00, MMS, NNN, NNN, C_CAL },  //'CALL'),
	{ 0x0000FF, 0x0000CB, 1, 00, PRF, NNN, NNN, C_RET },  //'RETF'),
	{ 0x0000FF, 0x0000CA, 1, 00, IM2, PRF, NNN, C_RET },  //'RETF'),
	{ 0x00FFFF, 0x00A40F, 2, 00, MRG, REG, IMS, C_CMD },  //'SHLD'),
	{ 0x00FFFF, 0x00AC0F, 2, 00, MRG, REG, IMS, C_CMD },  //'SHRD'),
	{ 0x00FFFF, 0x00A50F, 2, 00, MRG, REG, RCL, C_CMD },  //'SHLD'),
	{ 0x00FFFF, 0x00AD0F, 2, 00, MRG, REG, RCL, C_CMD },  //'SHRD'),
	{ 0x00F8FF, 0x00C80F, 2, 00, RCM, NNN, NNN, C_CMD },  //'BSWAP'),
	{ 0x00FEFF, 0x00C00F, 2, WW, MRG, REG, NNN, C_CMD },  //'XADD'),
	{ 0x0000FF, 0x0000E2, 1, LL, JOB, PCX, NNN, C_CMD },  //'$LOOP*'),
	{ 0x0000FF, 0x0000E1, 1, LL, JOB, PCX, NNN, C_CMD },  //'$LOOP*E'),
	{ 0x0000FF, 0x0000E0, 1, LL, JOB, PCX, NNN, C_CMD },  //'$LOOP*NE'),
	{ 0x0000FF, 0x0000C8, 1, 00, IM2, IM1, NNN, C_ENTER },  //'ENTER'),
	{ 0x0000FE, 0x0000E4, 1, WP, RAC, IM1, NNN, C_CMD },  //'IN'),
	{ 0x0000FE, 0x0000EC, 1, WP, RAC, RDX, NNN, C_CMD },  //'IN'),
	{ 0x0000FE, 0x0000E6, 1, WP, IM1, RAC, NNN, C_CMD },  //'OUT'),
	{ 0x0000FE, 0x0000EE, 1, WP, RDX, RAC, NNN, C_CMD },  //'OUT'),
	{ 0x0000FE, 0x00006C, 1, WP, MDE, RDX, NNN, C_CMD },  //'INS'),
	{ 0x0000FE, 0x00006E, 1, WP, RDX, MDE, NNN, C_CMD },  //'OUTS'),
	{ 0x00FEFF, 0x006CF3, 1, WP, MDE, RDX, PCX, C_REP },  //'REP INS'),
	{ 0x00FEFF, 0x006EF3, 1, WP, RDX, MDE, PCX, C_REP },  //'REP OUTS'),
	{ 0x0000FF, 0x000037, 1, 00, NNN, NNN, NNN, C_CMD },  //'AAA'),
	{ 0x0000FF, 0x00003F, 1, 00, NNN, NNN, NNN, C_CMD },  //'AAS'),
	{ 0x00FFFF, 0x000AD4, 2, 00, NNN, NNN, NNN, C_CMD },  //'AAM'),
	{ 0x0000FF, 0x0000D4, 1, 00, IM1, NNN, NNN, C_CMD },  //'AAM'),
	{ 0x00FFFF, 0x000AD5, 2, 00, NNN, NNN, NNN, C_CMD },  //'AAD'),
	{ 0x0000FF, 0x0000D5, 1, 00, IM1, NNN, NNN, C_CMD },  //'AAD'),
	{ 0x0000FF, 0x000027, 1, 00, NNN, NNN, NNN, C_CMD },  //'DAA'),
	{ 0x0000FF, 0x00002F, 1, 00, NNN, NNN, NNN, C_CMD },  //'DAS'),
	{ 0x0000FF, 0x0000F4, 1, PR, NNN, NNN, NNN, C_PRI },  //'HLT'),
	{ 0x0000FF, 0x00000E, 1, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FF, 0x000016, 1, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FF, 0x00001E, 1, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FF, 0x000006, 1, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x00FFFF, 0x00A00F, 2, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x00FFFF, 0x00A80F, 2, 00, SCM, NNN, NNN, C_PSH },  //'PUSH'),
	{ 0x0000FF, 0x00001F, 1, 00, SCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x0000FF, 0x000007, 1, 00, SCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x0000FF, 0x000017, 1, 00, SCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x00FFFF, 0x00A10F, 2, 00, SCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x00FFFF, 0x00A90F, 2, 00, SCM, NNN, NNN, C_POP },  //'POP'),
	{ 0x0000FF, 0x0000D7, 1, 00, MXL, NNN, NNN, C_CMD },  //'XLAT'),
	{ 0x00FFFF, 0x00BE0F, 2, 00, REG, MR1, NNN, C_MOVSX },  //'MOVSX'),
	{ 0x00FFFF, 0x00B60F, 2, 00, REG, MR1, NNN, C_MOVZX },  //'MOVZX'),
	{ 0x00FFFF, 0x00B70F, 2, 00, REG, MR2, NNN, C_MOVZX },  //'MOVZX'),
	{ 0x0000FF, 0x00009B, 1, 00, NNN, NNN, NNN, C_CMD },  //'WAIT'),
	{ 0x0000FF, 0x00009F, 1, 00, PAH, PFL, NNN, C_CMD },  //'LAHF'),
	{ 0x0000FF, 0x00009E, 1, 00, PFL, PAH, NNN, C_CMD },  //'SAHF'),
	{ 0x0000FF, 0x00009C, 1, 00, NNN, NNN, NNN, C_PSHF },  //'&PUSHF*'),
	{ 0x0000FF, 0x00009D, 1, 00, NNN, NNN, NNN, C_POPF },  //'&POPF*'),
	{ 0x0000FF, 0x0000CD, 1, 00, IM1, NNN, NNN, C_INT },  //'INT'),
	{ 0x0000FF, 0x0000CC, 1, 00, NNN, NNN, NNN, C_INT3 },  //'INT3'),
	{ 0x0000FF, 0x0000CE, 1, 00, NNN, NNN, NNN, C_CMD },  //'INTO'),
	{ 0x0000FF, 0x0000CF, 1, 00, NNN, NNN, NNN, C_RTF },  //'&IRET*'),
	{ 0x00FFFF, 0x00900F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETO'),
	{ 0x00FFFF, 0x00910F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETNO'),
	{ 0x00FFFF, 0x00920F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETB,SETC'),
	{ 0x00FFFF, 0x00930F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETNB,SETNC'),
	{ 0x00FFFF, 0x00940F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETE,SETZ'),
	{ 0x00FFFF, 0x00950F, 2, CC, MR1, NNN, NNN, C_SETNE },  //'SETNE,SETNZ'),
	{ 0x00FFFF, 0x00960F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETBE,SETNA'),
	{ 0x00FFFF, 0x00970F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETA,SETNBE'),
	{ 0x00FFFF, 0x00980F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETS'),
	{ 0x00FFFF, 0x00990F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETNS'),
	{ 0x00FFFF, 0x009A0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETPE,SETP'),
	{ 0x00FFFF, 0x009B0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETPO,SETNP'),
	{ 0x00FFFF, 0x009C0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETL,SETNGE'),
	{ 0x00FFFF, 0x009D0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETGE,SETNL'),
	{ 0x00FFFF, 0x009E0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETLE,SETNG'),
	{ 0x00FFFF, 0x009F0F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETG,SETNLE'),
	{ 0x38FFFF, 0x20BA0F, 2, 00, MRG, IM1, NNN, C_CMD },  //'BT'),
	{ 0x38FFFF, 0x28BA0F, 2, 00, MRG, IM1, NNN, C_CMD },  //'BTS'),
	{ 0x38FFFF, 0x30BA0F, 2, 00, MRG, IM1, NNN, C_CMD },  //'BTR'),
	{ 0x38FFFF, 0x38BA0F, 2, 00, MRG, IM1, NNN, C_CMD },  //'BTC'),
	{ 0x00FFFF, 0x00A30F, 2, 00, MRG, REG, NNN, C_CMD },  //'BT'),
	{ 0x00FFFF, 0x00AB0F, 2, 00, MRG, REG, NNN, C_CMD },  //'BTS'),
	{ 0x00FFFF, 0x00B30F, 2, 00, MRG, REG, NNN, C_CMD },  //1'BTR'),
	{ 0x00FFFF, 0x00BB0F, 2, 00, MRG, REG, NNN, C_CMD },  //'BTC'),
	{ 0x0000FF, 0x0000C5, 1, 00, REG, MML, NNN, C_CMD },  //'LDS'),
	{ 0x0000FF, 0x0000C4, 1, 00, REG, MML, NNN, C_CMD },  //'LES'),
	{ 0x00FFFF, 0x00B40F, 2, 00, REG, MML, NNN, C_CMD },  //'LFS'),
	{ 0x00FFFF, 0x00B50F, 2, 00, REG, MML, NNN, C_CMD },  //'LGS'),
	{ 0x00FFFF, 0x00B20F, 2, 00, REG, MML, NNN, C_CMD },  //'LSS'),
	{ 0x0000FF, 0x000063, 1, 00, MRG, REG, NNN, C_CMD },  //'ARPL'),
	{ 0x0000FF, 0x000062, 1, 00, REG, MMB, NNN, C_CMD },  //'BOUND'),
	{ 0x00FFFF, 0x00BC0F, 2, 00, REG, MRG, NNN, C_CMD },  //'BSF'),
	{ 0x00FFFF, 0x00BD0F, 2, 00, REG, MRG, NNN, C_CMD },  //'BSR'),
	{ 0x00FFFF, 0x00060F, 2, PR, NNN, NNN, NNN, C_CMD },  //'CLTS'),
	{ 0x00FFFF, 0x00400F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVO'),
	{ 0x00FFFF, 0x00410F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVNO'),
	{ 0x00FFFF, 0x00420F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVB,CMOVC'),
	{ 0x00FFFF, 0x00430F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVNB,CMOVNC'),
	{ 0x00FFFF, 0x00440F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVE,CMOVZ'),
	{ 0x00FFFF, 0x00450F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVNE,CMOVNZ'),
	{ 0x00FFFF, 0x00460F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVBE,CMOVNA'),
	{ 0x00FFFF, 0x00470F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVA,CMOVNBE'),
	{ 0x00FFFF, 0x00480F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVS'),
	{ 0x00FFFF, 0x00490F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVNS'),
	{ 0x00FFFF, 0x004A0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVPE,CMOVP'),
	{ 0x00FFFF, 0x004B0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVPO,CMOVNP'),
	{ 0x00FFFF, 0x004C0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVL,CMOVNGE'),
	{ 0x00FFFF, 0x004D0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVGE,CMOVNL'),
	{ 0x00FFFF, 0x004E0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVLE,CMOVNG'),
	{ 0x00FFFF, 0x004F0F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVG,CMOVNLE'),
	{ 0x00FEFF, 0x00B00F, 2, WW, MRG, REG, NNN, C_CMD },  //'CMPXCHG'),
	{ 0x38FFFF, 0x08C70F, 2, 00, MD8, NNN, NNN, C_CMD },  //'CMPXCHG8B'),
	{ 0x00FFFF, 0x00A20F, 2, 00, NNN, NNN, NNN, C_CMD },  //'CPUID'),
	{ 0x00FFFF, 0x00080F, 2, PR, NNN, NNN, NNN, C_CMD },  //'INVD'),
	{ 0x00FFFF, 0x00020F, 2, 00, REG, MRG, NNN, C_CMD },  //'LAR'),
	{ 0x00FFFF, 0x00030F, 2, 00, REG, MRG, NNN, C_CMD },  //'LSL'),
	{ 0x38FFFF, 0x38010F, 2, PR, MR1, NNN, NNN, C_CMD },  //'INVLPG'),
	{ 0x00FFFF, 0x00090F, 2, PR, NNN, NNN, NNN, C_CMD },  //'WBINVD'),
	{ 0x38FFFF, 0x10010F, 2, PR, MM6, NNN, NNN, C_CMD },  //'LGDT'),
	{ 0x38FFFF, 0x00010F, 2, 00, MM6, NNN, NNN, C_CMD },  //'SGDT'),
	{ 0x38FFFF, 0x18010F, 2, PR, MM6, NNN, NNN, C_CMD },  //'LIDT'),
	{ 0x38FFFF, 0x08010F, 2, 00, MM6, NNN, NNN, C_CMD },  //'SIDT'),
	{ 0x38FFFF, 0x10000F, 2, PR, MR2, NNN, NNN, C_CMD },  //'LLDT'),
	{ 0x38FFFF, 0x00000F, 2, 00, MR2, NNN, NNN, C_CMD },  //'SLDT'),
	{ 0x38FFFF, 0x18000F, 2, PR, MR2, NNN, NNN, C_CMD },  //'LTR'),
	{ 0x38FFFF, 0x08000F, 2, 00, MR2, NNN, NNN, C_CMD },  //'STR'),
	{ 0x38FFFF, 0x30010F, 2, PR, MR2, NNN, NNN, C_CMD },  //'LMSW'),
	{ 0x38FFFF, 0x20010F, 2, 00, MR2, NNN, NNN, C_CMD },  //'SMSW'),
	{ 0x38FFFF, 0x20000F, 2, 00, MR2, NNN, NNN, C_CMD },  //'VERR'),
	{ 0x38FFFF, 0x28000F, 2, 00, MR2, NNN, NNN, C_CMD },  //'VERW'),
	{ 0xC0FFFF, 0xC0220F, 2, PR, CRX, RR4, NNN, C_MOV },  //'MOV'),
	{ 0xC0FFFF, 0xC0200F, 2, 00, RR4, CRX, NNN, C_MOV },  //'MOV'),
	{ 0xC0FFFF, 0xC0230F, 2, PR, DRX, RR4, NNN, C_MOV },  //'MOV'),
	{ 0xC0FFFF, 0xC0210F, 2, PR, RR4, DRX, NNN, C_MOV },  //'MOV'),
	{ 0x00FFFF, 0x00310F, 2, 00, NNN, NNN, NNN, C_CMD },  //'RDTSC'),
	{ 0x00FFFF, 0x00320F, 2, PR, NNN, NNN, NNN, C_CMD },  //'RDMSR'),
	{ 0x00FFFF, 0x00300F, 2, PR, NNN, NNN, NNN, C_CMD },  //'WRMSR'),
	{ 0x00FFFF, 0x00330F, 2, PR, NNN, NNN, NNN, C_CMD },  //'RDPMC'),
	{ 0x00FFFF, 0x00AA0F, 2, PR, NNN, NNN, NNN, C_RTF },  //'RSM'),
	{ 0x00FFFF, 0x000B0F, 2, 00, NNN, NNN, NNN, C_CMD },  //'UD2'),
	{ 0x00FFFF, 0x00340F, 2, 00, NNN, NNN, NNN, C_SYSENTER },  //'SYSENTER'),
	{ 0x00FFFF, 0x00350F, 2, PR, NNN, NNN, NNN, C_SYSEXIT },  //'SYSEXIT'),
	{ 0x0000FF, 0x0000D6, 1, 00, NNN, NNN, NNN, C_CMD },  //'SALC'),

														  // Some alternative mnemonics for Assembler, not used by Disassembler (so
														  // implicit pseudooperands are not marked).
	{ 0x0000FF, 0x0000A6, 1, 00, NNN, NNN, NNN, C_CMPSB },  //'CMPSB'),
	{ 0x00FFFF, 0x00A766, 2, 00, NNN, NNN, NNN, C_CMPSW },  //'CMPSW'),
	{ 0x0000FF, 0x0000A7, 1, 00, NNN, NNN, NNN, C_CMPSD },  //'CMPSD'),
	{ 0x0000FF, 0x0000AC, 1, 00, NNN, NNN, NNN, C_CMD },  //'LODSB'),
	{ 0x00FFFF, 0x00AD66, 2, 00, NNN, NNN, NNN, C_CMD },  //'LODSW'),
	{ 0x0000FF, 0x0000AD, 1, 00, NNN, NNN, NNN, C_CMD },  //'LODSD'),
	{ 0x0000FF, 0x0000A4, 1, 00, NNN, NNN, NNN, C_MOVSB },  //'MOVSB'),
	{ 0x00FFFF, 0x00A566, 2, 00, NNN, NNN, NNN, C_MOVSW },  //'MOVSW'),
	{ 0x0000FF, 0x0000A5, 1, 00, NNN, NNN, NNN, C_MOVSD },  //'MOVSD'),
	{ 0x0000FF, 0x0000AE, 1, 00, NNN, NNN, NNN, C_CMD },  //'SCASB'),
	{ 0x00FFFF, 0x00AF66, 1, 00, NNN, NNN, NNN, C_CMD },  //'SCASW'),
	{ 0x0000FF, 0x0000AF, 1, 00, NNN, NNN, NNN, C_CMD },  //'SCASD'),
	{ 0x0000FF, 0x0000AA, 1, 00, NNN, NNN, NNN, C_CMD },  //'STOSB'),
	{ 0x00FFFF, 0x00AB66, 2, 00, NNN, NNN, NNN, C_CMD },  //'STOSW'),
	{ 0x0000FF, 0x0000AB, 1, 00, NNN, NNN, NNN, C_CMD },  //'STOSD'),
	{ 0x00FFFF, 0x00A4F3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP MOVSB'),
	{ 0xFFFFFF, 0xA5F366, 2, 00, NNN, NNN, NNN, C_REP },  //'REP MOVSW'),
	{ 0x00FFFF, 0x00A5F3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP MOVSD'),
	{ 0x00FFFF, 0x00ACF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP LODSB'),
	{ 0xFFFFFF, 0xADF366, 2, 00, NNN, NNN, NNN, C_REP },  //'REP LODSW'),
	{ 0x00FFFF, 0x00ADF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP LODSD'),
	{ 0x00FFFF, 0x00AAF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP STOSB'),
	{ 0xFFFFFF, 0xABF366, 2, 00, NNN, NNN, NNN, C_REP },  //'REP STOSW'),
	{ 0x00FFFF, 0x00ABF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP STOSD'),
	{ 0x00FFFF, 0x00A6F3, 1, 00, NNN, NNN, NNN, C_REP },  //'REPE CMPSB'),
	{ 0xFFFFFF, 0xA7F366, 2, 00, NNN, NNN, NNN, C_REP },  //'REPE CMPSW'),
	{ 0x00FFFF, 0x00A7F3, 1, 00, NNN, NNN, NNN, C_REP },  //'REPE CMPSD'),
	{ 0x00FFFF, 0x00AEF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REPE SCASB'),
	{ 0xFFFFFF, 0xAFF366, 2, 00, NNN, NNN, NNN, C_REP },  //'REPE SCASW'),
	{ 0x00FFFF, 0x00AFF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REPE SCASD'),
	{ 0x00FFFF, 0x00A6F2, 1, 00, NNN, NNN, NNN, C_REP },  //'REPNE CMPSB'),
	{ 0xFFFFFF, 0xA7F266, 2, 00, NNN, NNN, NNN, C_REP },  //'REPNE CMPSW'),
	{ 0x00FFFF, 0x00A7F2, 1, 00, NNN, NNN, NNN, C_REP },  //'REPNE CMPSD'),
	{ 0x00FFFF, 0x00AEF2, 1, 00, NNN, NNN, NNN, C_REP },  //'REPNE SCASB'),
	{ 0xFFFFFF, 0xAFF266, 2, 00, NNN, NNN, NNN, C_REP },  //'REPNE SCASW'),
	{ 0x00FFFF, 0x00AFF2, 1, 00, NNN, NNN, NNN, C_REP },  //'REPNE SCASD'),
	{ 0x0000FF, 0x00006C, 1, 00, NNN, NNN, NNN, C_CMD },  //'INSB'),
	{ 0x00FFFF, 0x006D66, 2, 00, NNN, NNN, NNN, C_CMD },  //'INSW'),
	{ 0x0000FF, 0x00006D, 1, 00, NNN, NNN, NNN, C_CMD },  //'INSD'),
	{ 0x0000FF, 0x00006E, 1, 00, NNN, NNN, NNN, C_CMD },  //'OUTSB'),
	{ 0x00FFFF, 0x006F66, 2, 00, NNN, NNN, NNN, C_CMD },  //'OUTSW'),
	{ 0x0000FF, 0x00006F, 1, 00, NNN, NNN, NNN, C_CMD },  //'OUTSD'),
	{ 0x00FFFF, 0x006CF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP INSB'),
	{ 0xFFFFFF, 0x6DF366, 2, 00, NNN, NNN, NNN, C_REP },  //'REP INSW'),
	{ 0x00FFFF, 0x006DF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP INSD'),
	{ 0x00FFFF, 0x006EF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP OUTSB'),
	{ 0xFFFFFF, 0x6FF366, 2, 00, NNN, NNN, NNN, C_REP },  //'REP OUTSW'),
	{ 0x00FFFF, 0x006FF3, 1, 00, NNN, NNN, NNN, C_REP },  //'REP OUTSD'),
	{ 0x0000FF, 0x0000E1, 1, 00, JOB, NNN, NNN, C_CMD },  //'$LOOP*Z'),
	{ 0x0000FF, 0x0000E0, 1, 00, JOB, NNN, NNN, C_CMD },  //'$LOOP*NZ'),
	{ 0x0000FF, 0x00009B, 1, 00, NNN, NNN, NNN, C_CMD },  //'FWAIT'),
	{ 0x0000FF, 0x0000D7, 1, 00, NNN, NNN, NNN, C_CMD },  //'XLATB'),
	{ 0x00FFFF, 0x00C40F, 2, 00, RMX, RR4, IM1, C_MMX },  //'PINSRW'),
	{ 0x00FFFF, 0x0020CD, 2, 00, VXD, NNN, NNN, C_CMD },  //'VxDCall'),

	{ 0x0000F0, 0x000070, 1, CC, JOB, NNN, NNN, C_JMC },  //'JCC'),
	{ 0x00F0FF, 0x00800F, 2, CC, JOW, NNN, NNN, C_JMC },  //'JCC'),
	{ 0x00F0FF, 0x00900F, 2, CC, MR1, NNN, NNN, C_CMD },  //'SETCC'),
	{ 0x00F0FF, 0x00400F, 2, CC, REG, MRG, NNN, C_CMD },  //'CMOVCC'),

	{ 0x000000, 0x000000, 0, 00, NNN, NNN, NNN, C_CMD }  //'')
};

static UCHAR hexs[] =
{
	0x0,0x1,0x2,0x3,
	0x4,0x5,0x6,0x7,
	0x8,0x9,0xA,0xB,
	0xC,0xD,0xE,0xF
};

UCHAR Disasm::CharToHex(UCHAR * ch)
{
	unsigned char temps[2] = { 0 };
	for (int i = 0; i < 2; i++)
	{
		if (ch[i] >= '0' && ch[i] <= '9')
		{
			temps[i] = (ch[i] - '0');
		}
		else if (ch[i] >= 'A' && ch[i] <= 'F')
		{
			temps[i] = (ch[i] - 'A') + 0xA;
		}
		else if (ch[i] >= 'a' && ch[i] <= 'f')
		{
			temps[i] = (ch[i] - 'a') + 0xA;
		}
	}
	return ((temps[0] << 4) & 0xf0) | (temps[1] & 0xf);
}


string Disasm::StrCodeToHexStr(string code)
{
	const char * pTemp = code.c_str();
	string str = "";
	int size = code.size() / 2;
	for (int i = 0; i < size; i++) 
	{
		str += CharToHex((PUCHAR)pTemp);
		pTemp += 2;
	}
	return str;
}


VOID Disasm::DecodeIM(ULONG constsize) {
	ULONG l;

	this->ImmSize+=constsize;
	l = 1+ this->HasRM + this->HasSIB + this->DispSize + (this->ImmSize - constsize);
	if (this->RemainingSize < l+constsize) this->error = DAE_CROSS;
}

VOID Disasm::DecodeVX(VOID) {
	ULONG l;

	this->ImmSize+=4;

	l=1+ this->HasRM + this->HasSIB + this->DispSize + (this->ImmSize - 4);
	if (this->RemainingSize < l+4)
	{
		this->error=DAE_CROSS;
		return; 
	}
}

void Disasm::DecodeRJ(ULONG offsize)
{
	if (this->RemainingSize < offsize+1)
	{
		this->error=DAE_CROSS;
		return; 
	}
	this->DispSize = offsize;
}


VOID Disasm::DecodeMR(ULONG type)
{
  ULONG sib;
  ULONG	c;

  if (this->RemainingSize<2)
  {
	  this->error=DAE_CROSS;
	return; 
  }

  this->HasRM=1;

  c= this->Cmd[1] & 0xC7;

  if ( (c & 0xC0) == 0xC0 ) return; 

  if (this->AddrSize==2)
  {
    if ( c == 0x06 ) 
	{
		this->DispSize=2;
      if (this->RemainingSize<4) this->error=DAE_CROSS;
	}
    else
	{
      if ((c & 0xC0)==0x40) 
	  {
        if (this->RemainingSize<3) this->error=DAE_CROSS;
		this->DispSize=1;
	  }
      else if ((c & 0xC0)==0x80) 
	  {
        if (this->RemainingSize<4) this->error=DAE_CROSS;
		this->DispSize=2;
	  }
    }
  } 
  else if ( c == 0x05) 
  {
	  this->DispSize=4;
    if (this->RemainingSize<6) this->error=DAE_CROSS;
  }
  else if ((c & 0x07)==0x04) 
  {         // SIB addresation
    sib= this->Cmd[2];
	this->HasSIB=1;

    if (c==0x04 && (sib & 0x07)==0x05) 
	{
		this->DispSize=4;                      // Immediate address without base
      if (this->RemainingSize<7)
		  this->error=DAE_CROSS;           // Disp32 outside the memory block
	}
    else 
	{                             // Base and, eventually, displacement
      if ((c & 0xC0)==0x40) 
	  {
		  this->DispSize=1;
        if (this->RemainingSize<4) this->error=DAE_CROSS;
      }
      else if ((c & 0xC0)==0x80) 
	  {
		  this->DispSize=4;
        if (this->RemainingSize<7) this->error=DAE_CROSS;
      }
    }
  }
  else 
  {                               // No SIB
	  if ((c & 0xC0)==0x40) 
	  {
		  this->DispSize=1;
		  if (this->RemainingSize<3) this->error = DAE_CROSS;
	  }
	  else if ((c & 0xC0)==0x80) 
	  {
		  this->DispSize=4;
		  if (this->RemainingSize<6) this->error = DAE_CROSS;
	  }
	  
  }
}

ULONG Disasm::DisasmCodeStr(PCHAR Src, ULONG SrcSize)
{
	string str = this->StrCodeToHexStr(Src);
	return this->DisasmCode((PUCHAR)str.c_str(), SrcSize);
}

ULONG Disasm::DisasmCode(PUCHAR Src,ULONG SrcSize)
{
  ULONG operand,arg;
  PCmdData pd;

  ULONG Code = 0;
  ULONG LockPrefix = 0;	//锁定前缀
  ULONG RepPrefix = 0;	//重复前缀
  BOOLEAN	Repeated = FALSE;
  BOOLEAN	IsPrefix;

  if (SrcSize == 0) return 0;
   
  this->DataSize = this->AddrSize=4;                 // 32-bit code and data segments only!
  this->SegPrefix = SEG_UNDEF;
  this->HasRM = this->HasSIB = 0;
  this->DispSize = this->ImmSize = 0;
  this->Cmd = Src;
  this->RemainingSize = SrcSize;

  this->cmdtype=C_BAD;
  this->warnings=0;
  this->error=DAE_NOERR;

  //处理前缀
  while (this->RemainingSize>0 )
  {
    IsPrefix = TRUE;
    switch (*this->Cmd)
	{
      case 0x26: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_ES; else Repeated=TRUE; break;
      case 0x2E: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_CS; else Repeated=TRUE; break;
      case 0x36: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_SS; else Repeated=TRUE; break;
      case 0x3E: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_DS; else Repeated=TRUE; break;
      case 0x64: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_FS; else Repeated=TRUE; break;
      case 0x65: if (this->SegPrefix == SEG_UNDEF) this->SegPrefix = SEG_GS; else Repeated=TRUE; break;
      case 0x66: if (this->DataSize == 4) this->DataSize = 2; else Repeated = TRUE; break;
      case 0x67: if (this->AddrSize == 4) this->AddrSize = 2; else Repeated = TRUE; break;
      case 0xF0: if (LockPrefix == 0) LockPrefix = 0xF0; else Repeated = TRUE; break;
      case 0xF2: if (RepPrefix == 0) RepPrefix = 0xF2; else Repeated = TRUE; break;
      case 0xF3: if (RepPrefix == 0) RepPrefix = 0xF3; else Repeated = TRUE; break;

      default: 
		IsPrefix = FALSE; 
		break; 
	}
    if (IsPrefix == FALSE || Repeated == TRUE) break;

    this->Cmd++; 
	this->RemainingSize--; 
  }//end while
  
  //重复前缀
  if ( Repeated ) 
  {
	this->cmdtype = C_RARE;
	return 1;
  }

  //锁定前缀指示
  if ( LockPrefix != 0 ) this->warnings|=DAW_LOCK;

  //取出指令三个字节 如果够长的话
  if (this->RemainingSize>0) *(((PUCHAR)&Code)+0) =this->Cmd[0];
  if (this->RemainingSize>1) *(((PUCHAR)&Code)+1) =this->Cmd[1];
  if (this->RemainingSize>2) *(((PUCHAR)&Code)+2) =this->Cmd[2];

  //如果有前缀的话 添加到双字中
  if (RepPrefix!=0) Code = (Code<<8) | RepPrefix;        // part of command.

  //查表
  for ( pd = (PCmdData)&CmdDataTable[0]; pd->mask != 0; pd++ )
  {
	  if ( ((Code^pd->code) & pd->mask) != 0 ) continue;
	  break;
  }


  //没找到
  if ( pd->mask==0 ) 
  {
	  this->cmdtype=C_BAD;
    if (this->RemainingSize<2) this->error = DAE_CROSS;  //没发现指令的话写入error
    else this->error=DAE_BADCMD;
  }
  else //发现了指令 开始解码
  {
	  this->cmdtype = pd->type;

	//特权指令
    if (pd->bits==PR) this->warnings|=DAW_PRIV;
    else if (pd->bits==WP) this->warnings|=DAW_IO;//io指令

	//因为不能出现inc esp , dec esp , add esp,imm sub esp,imm这里进行判断 <会造成堆栈不平衡>
    if (this->Cmd[0]==0x44 || this->Cmd[0]==0x4C ||
      ( this->RemainingSize>=3 && (this->Cmd[0]==0x81 || this->Cmd[0]==0x83) &&
      (this->Cmd[1]==0xC4 || this->Cmd[1]==0xEC) && (this->Cmd[2] & 0x03)!=0))
	{
      this->warnings|=DAW_STACK;
      this->cmdtype|=C_RARE; 
	}

	//修改段寄存器指令
    if (this->Cmd[0]==0x8E) this->warnings|=DAW_SEGMENT;

    //2字节操作码
    if (pd->len==2) 
	{
      if (this->RemainingSize==0) this->error=DAE_CROSS;
      else 
	  {
        this->Cmd++; 
		this->RemainingSize--;
      }
	}

	//如果已经到达了缓冲末尾   错误信息
    if (this->RemainingSize==0) this->error=DAE_CROSS;

    if ((pd->bits & WW)!=0 && (*this->Cmd & WW)==0)
      this->DataSize=1;
    else if ((pd->bits & W3)!=0 && (*this->Cmd & W3)==0)
      this->DataSize=1;
    else if ((pd->bits & FF)!=0)
      this->DataSize=2;


    for (operand=0; operand<3; operand++) 
	{
      if (this->error) break;
      if (operand==0) arg = pd->arg1;
      else if (operand==1) arg=pd->arg2;
      else arg=pd->arg3;
      if (arg==NNN) break;

      switch (arg) {
		case REG: case RG4: case RMX: case R3D: case SGM:
			if (this->RemainingSize < 2) this->error=DAE_CROSS;
			this->HasRM=1; 
			break;

        case MRG: case MRJ: case MRD:
        case MR1: case MR2: case MR4: case MR8:
		case MMA: case MMB: case MML: case MMS: case MM6:
		case MD2: case MD4: case MD8: case MDA:
        case MB2:
		case MF4: case MF8: case MFA: case MFE: case MFS: case MFX:
		case RR4: case RR8: case RRD:
          DecodeMR(arg); 
		  break;

		case IMM:                      // Immediate data (8 or 16/32)
		case IMU:                      // Immediate unsigned data (8 or 16/32)
			if ((pd->bits & SS)!=0 && (*this->Cmd & 0x02)!=0) DecodeIM(1);
			else DecodeIM(this->DataSize);
			break;

		case IMA:                      // Immediate absolute near data address
			if (this->RemainingSize < 1 + this->AddrSize)
				this->error = DAE_CROSS;
			else
				this->DispSize = this->AddrSize;
			break;

		case VXD:
			DecodeVX(); 
			break;
			break;
		case JOB:
			DecodeRJ(1); 
			break;
		case JOW:
			DecodeRJ(this->DataSize);
			break;
		case IM2:
			DecodeIM(2);
			break;		
		case IMX: case IMS:	case IM1:
			DecodeIM(1); 
			break;

		case JMF:
			if (this->RemainingSize < 1+ this->AddrSize+2 )
				this->error = DAE_CROSS;
			else
			{
				this->DispSize = this->AddrSize;
				this->ImmSize = 2;
			}
			break;

		case CRX:
		case DRX:
			if ((this->Cmd[1] & 0xC0)!=0xC0) this->error=DAE_REGISTER;
			this->HasRM = 1;
			break;

		case PRN: case PRF: case PAC: case PAH: case PFL: case PS0:	case PS1:
		case PCX: case PDI: case SCM: case C01: case RCM: case RAC:	case RAX:
		case RDX: case RCL:	case RS0: case RST:	case MSO: case MDE:	case MXL:
			break;   

        default:
			this->error=DAE_INTERN;        // Unknown argument type
        break;
      }
	 }//end for
	}//if ( (pd->mask==0)||((pd->type & C_TYPEMASK) == C_NOW) ) 

	if (this->error!=0)
	{
		if (this->error==DAE_BADCMD && (*this->Cmd==0x0F || *this->Cmd==0xFF) && this->RemainingSize>0)
			this->RemainingSize--;

		if (this->RemainingSize>0)
			this->RemainingSize--;
	}
	else 	  
		this->RemainingSize -= 1+ this->HasRM+ this->HasSIB+ this->DispSize+ this->ImmSize;
  return (SrcSize - this->RemainingSize);
}

