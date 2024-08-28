/* Capstone Disassembly Engine */
/* By Giovanni Dante Grazioli, deroad <wargio@libero.it>, 2024 */

#ifdef CAPSTONE_HAS_MIPS

#include <stdio.h>
#include <string.h>

#include <capstone/capstone.h>
#include <capstone/mips.h>

#include "../../Mapping.h"
#include "../../MCDisassembler.h"
#include "../../cs_priv.h"
#include "../../cs_simple_types.h"

#include "MipsMapping.h"
#include "MipsLinkage.h"
#include "MipsDisassembler.h"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "MipsGenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "MipsGenInstrInfo.inc"

void Mips_init_mri(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(MRI, MipsRegDesc,
					  sizeof(MipsRegDesc), 0, 0,
					  MipsMCRegisterClasses,
					  ARR_SIZE(MipsMCRegisterClasses),
					  0, 0, MipsRegDiffLists, 0,
					  MipsSubRegIdxLists,
					  ARR_SIZE(MipsSubRegIdxLists), 0);
}

const char *Mips_reg_name(csh handle, unsigned int reg)
{
	return Mips_LLVM_getRegisterName(reg);
}

void Mips_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by Mips. Information is set after disassembly.
}

static const char *const insn_name_maps[] = {
#include "MipsGenCSMappingInsnName.inc"
};

const char *Mips_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id < ARR_SIZE(insn_name_maps))
		return insn_name_maps[id];
	// not found
	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	{ MIPS_GRP_INVALID, NULL },

	{ MIPS_GRP_JUMP, "jump" },
	{ MIPS_GRP_CALL, "call" },
	{ MIPS_GRP_RET, "return" },
	{ MIPS_GRP_INT, "int" },
	{ MIPS_GRP_IRET, "iret" },
	{ MIPS_GRP_PRIVILEGE, "privilege" },
	{ MIPS_GRP_BRANCH_RELATIVE, "branch_relative" },

// architecture-specific groups
#include "MipsGenCSFeatureName.inc"
};
#endif

const char *Mips_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

const insn_map mips_insns[] = {
#include "MipsGenCSMappingInsn.inc"
};

void Mips_set_instr_map_data(MCInst *MI) 
{
	map_cs_id(MI, mips_insns, ARR_SIZE(mips_insns));
	map_implicit_reads(MI, mips_insns);
	map_implicit_writes(MI, mips_insns);
	map_groups(MI, mips_insns);
}

bool Mips_getInstruction(csh handle, const uint8_t *code, size_t code_len,
			      MCInst *instr, uint16_t *size, uint64_t address,
			      void *info)
{
	uint64_t size64;
	Mips_init_cs_detail(instr);
	instr->MRI = (MCRegisterInfo *)info;

	cs_struct *ud = (cs_struct *)handle;
	bool result = Mips_LLVM_getInstruction(instr, &size64, code,
						    code_len, address, info,
						    ud->mode)
						    != MCDisassembler_Fail;
	if (result) {
		Mips_set_instr_map_data(instr);
	}
	*size = size64;
	return result;
}

void Mips_printer(MCInst *MI, SStream *O,
		       void * /* MCRegisterInfo* */ info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)info;
	MI->MRI = MRI;

	Mips_LLVM_printInst(MI, MI->address, O);
}

static void Mips_setup_op(cs_mips_op *op)
{
	memset(op, 0, sizeof(cs_mips_op));
	op->type = MIPS_OP_INVALID;
}

void Mips_init_cs_detail(MCInst *MI)
{
	if (detail_is_set(MI)) {
		unsigned int i;

		memset(get_detail(MI), 0,
		       offsetof(cs_detail, mips) + sizeof(cs_mips));

		for (i = 0; i < ARR_SIZE(Mips_get_detail(MI)->operands);
		     i++)
			Mips_setup_op(
				&Mips_get_detail(MI)->operands[i]);
	}
}

static const map_insn_ops insn_operands[] = {
#include "MipsGenCSMappingInsnOp.inc"
};

static void Mips_set_detail_op_mem_reg(MCInst *MI, unsigned OpNum, mips_reg Reg)
{
	Mips_get_detail_op(MI, 0)->type = MIPS_OP_MEM;
	Mips_get_detail_op(MI, 0)->mem.base = Reg;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
}

static void Mips_set_detail_op_mem_disp(MCInst *MI, unsigned OpNum, int64_t Imm)
{
	Mips_get_detail_op(MI, 0)->type = MIPS_OP_MEM;
	Mips_get_detail_op(MI, 0)->mem.disp = Imm;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
}

void Mips_set_detail_op_imm(MCInst *MI, unsigned OpNum,
				 mips_op_type ImmType, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;

	if (doing_mem(MI)) {
		Mips_set_detail_op_mem_disp(MI, OpNum, Imm);
		return;
	}

	assert(ImmType == MIPS_OP_IMM);

	Mips_get_detail_op(MI, 0)->type = ImmType;
	Mips_get_detail_op(MI, 0)->imm = Imm;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Mips_inc_op_count(MI);
}

void Mips_set_detail_op_reg(MCInst *MI, unsigned OpNum, mips_reg Reg)
{
	if (!detail_is_set(MI))
		return;

	if (doing_mem(MI)) {
		Mips_set_detail_op_mem_reg(MI, OpNum, Reg);
		return;
	}

	assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	Mips_get_detail_op(MI, 0)->type = MIPS_OP_REG;
	Mips_get_detail_op(MI, 0)->reg = Reg;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Mips_inc_op_count(MI);
}

void Mips_set_mem_access(MCInst *MI, bool status)
{
	if (!detail_is_set(MI))
		return;
	set_doing_mem(MI, status);
	if (status) {
		if (Mips_get_detail(MI)->op_count > 0 &&
		    Mips_get_detail_op(MI, -1)->type == MIPS_OP_MEM &&
		    Mips_get_detail_op(MI, -1)->mem.disp == 0) {
			// Previous memory operand not done yet. Select it.
			Mips_dec_op_count(MI);
			return;
		}

		// Init a new one.
		Mips_get_detail_op(MI, 0)->type = MIPS_OP_MEM;
		Mips_get_detail_op(MI, 0)->mem.base = MIPS_REG_INVALID;
		Mips_get_detail_op(MI, 0)->mem.disp = 0;

#ifndef CAPSTONE_DIET
		uint8_t access =
			map_get_op_access(MI, Mips_get_detail(MI)->op_count);
		Mips_get_detail_op(MI, 0)->access = access;
#endif
	} else {
		// done, select the next operand slot
		Mips_inc_op_count(MI);
	}
}

#endif
