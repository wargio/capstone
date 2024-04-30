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

static void Mips_set_detail_op_imm(MCInst *MI, unsigned OpNum,
				 mips_op_type ImmType, int64_t Imm)
{
	if (!detail_is_set(MI))
		return;
	assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_IMM);
	assert(ImmType == MIPS_OP_IMM);

	Mips_get_detail_op(MI, 0)->type = ImmType;
	Mips_get_detail_op(MI, 0)->imm = Imm;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Mips_inc_op_count(MI);
}

static void Mips_set_detail_op_reg(MCInst *MI, unsigned OpNum, mips_reg Reg)
{
	if (!detail_is_set(MI))
		return;
	assert((map_get_op_type(MI, OpNum) & ~CS_OP_MEM) == CS_OP_REG);

	Mips_get_detail_op(MI, 0)->type = MIPS_OP_REG;
	Mips_get_detail_op(MI, 0)->reg = Reg;
	Mips_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
	Mips_inc_op_count(MI);
}

void Mips_add_cs_detail(MCInst *MI, int /* mips_op_group */ op_group,
			     va_list args)
{
	if (!detail_is_set(MI))
		return;

	unsigned OpNum = va_arg(args, unsigned);
	// Handle memory operands later
	cs_op_type op_type = map_get_op_type(MI, OpNum) & ~CS_OP_MEM;

	// Fill cs_detail
	switch (op_group) {
	default:
		printf("ERROR: Operand group %d not handled!\n", op_group);
		assert(0);
	case Mips_OP_GROUP_Operand:
		if (op_type == CS_OP_IMM) {
			Mips_set_detail_op_imm(MI, OpNum, MIPS_OP_IMM,
						    MCInst_getOpVal(MI, OpNum));
		} else if (op_type == CS_OP_REG) {
			Mips_set_detail_op_reg(MI, OpNum,
						    MCInst_getOpVal(MI, OpNum));
		} else
			assert(0 && "Op type not handled.");
		break;
	}
}

#endif
