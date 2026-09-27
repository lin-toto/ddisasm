//===- Arm64Loader.cpp ------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2020 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "Arm64Loader.h"

#include <algorithm>
#include <string>
#include <vector>

#include "Arm64Capstone.h"

void Arm64Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build facts from the current decoder, correcting only verified errors
    // in its access metadata rather than recreating older decoder behavior.
    bool InstAdded = false;
    if(Count > 0 && capstone_compat::adaptAArch64(*CsHandle, *CsInsn))
    {
        fixAArch64Capstone6Accesses(*CsInsn);
        InstAdded = build(Facts, *CsInsn);
    }

    if(InstAdded)
    {
        loadRegisterAccesses(Facts, Addr, *CsInsn);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
}

bool Arm64Loader::build(BinaryFacts& Facts, const cs_insn& CsInstruction)
{
    const cs_aarch64& Details = CsInstruction.detail->aarch64;
    std::string Name = uppercase(CsInstruction.mnemonic);
    gtirb::Addr Addr(CsInstruction.address);
    std::vector<uint64_t> OpCodes;

    // Capstone produces the ARM-preferred MOV alias for MOVZ as MOV when
    // the immediate fits a single 16-bit lane. In that case, the encoded
    // shift is folded into the final immediate value (for example,
    // "MOVZ X0, #0x40, LSL #16"
    // becomes
    // "MOV X0, #0x400000")
    // The mnemonic is MOV (and Capstone 6 reports the alias as MOV), so
    // recover the canonical MOVZ form by checking the raw instruction encoding
    // (opc == 10) and reconstructing the original imm16 + shift pair.
    // This allows the MOVZ+MOVK symbolization rules to match correctly.
    unsigned AliasedShift = 0;
    int64_t AliasedImm16 = 0;
    if(CsInstruction.is_alias && CsInstruction.alias_id == AARCH64_INS_ALIAS_MOV
       && Details.op_count == 2)
    {
        const cs_aarch64_op& Src = Details.operands[1];
        if(Src.type == AARCH64_OP_IMM)
        {
            uint32_t Enc = static_cast<uint32_t>(CsInstruction.bytes[0])
                           | (static_cast<uint32_t>(CsInstruction.bytes[1]) << 8)
                           | (static_cast<uint32_t>(CsInstruction.bytes[2]) << 16)
                           | (static_cast<uint32_t>(CsInstruction.bytes[3]) << 24);

            // bits[30:29] = opc, where 10 identifies MOVZ
            if(((Enc >> 29) & 0x3) == 0x2)
            {
                Name = "MOVZ";
                // bits[22:21] = shift/16  <==>  shift = bits[22:21] << 4
                AliasedShift = ((Enc >> 21) & 0x3) << 4;
                AliasedImm16 = (static_cast<uint64_t>(Src.imm) >> AliasedShift) & 0xFFFF;
            }
        }
    }

    if(Name != "NOP")
    {
        uint8_t OpCount = Details.op_count;
        for(uint8_t i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            cs_aarch64_op CsOp = Details.operands[i];
            // For aliased MOVZ, we fix up the immediate operand to recover the
            // original 16-bit value and shift that capstone folded away.
            if(CsOp.type == AARCH64_OP_IMM && AliasedShift > 0)
            {
                CsOp.imm = AliasedImm16;
                CsOp.shift.type = AARCH64_SFT_LSL;
                CsOp.shift.value = AliasedShift;
            }

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsInstruction, i, CsOp);
            if(!Op)
            {
                return false;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);

            // Populate shift metadata for immediate operands (e.g., MOVZ/MOVK
            // with lsl #16/#32/#48). This is needed for MOVZ+MOVK address
            // reconstruction in the Datalog symbolization rules.
            if(CsOp.type == AARCH64_OP_IMM && CsOp.shift.type == AARCH64_SFT_LSL)
            {
                Facts.Instructions.shiftedOp(
                    relations::ShiftedOp{Addr, rotated_op_index(i + 1, OpCount),
                                         static_cast<uint8_t>(CsOp.shift.value), "LSL"});
            }

            // Populate shift metadata if present.
            if(CsOp.type == AARCH64_OP_REG && CsOp.shift.value != 0)
            {
                std::string ShiftType;
                switch(CsOp.shift.type)
                {
                    case AARCH64_SFT_LSL:
                        ShiftType = "LSL";
                        break;
                    case AARCH64_SFT_MSL:
                        ShiftType = "MSL";
                        break;
                    case AARCH64_SFT_LSR:
                        ShiftType = "LSR";
                        break;
                    case AARCH64_SFT_ASR:
                        ShiftType = "ASR";
                        break;
                    case AARCH64_SFT_ROR:
                        ShiftType = "ROR";
                        break;
                    case AARCH64_SFT_INVALID:
                        std::cerr << "WARNING: instruction has a non-zero invalid shift at " << Addr
                                  << "\n";
                        return false;
                    default:
                        // Shifts by a register (AARCH64_SFT_*_REG) have no
                        // op_shifted representation.
                        std::cerr << "WARNING: instruction has an unsupported shift at " << Addr
                                  << "\n";
                        return false;
                }
                Facts.Instructions.shiftedOp(
                    relations::ShiftedOp{Addr, rotated_op_index(i + 1, OpCount),
                                         static_cast<uint8_t>(CsOp.shift.value), ShiftType});
            }

            // Populate extend metadata if present. We pass this as a shift type.
            if(CsOp.type == AARCH64_OP_REG && CsOp.ext != AARCH64_EXT_INVALID)
            {
                std::string ShiftType;
                switch(CsOp.ext)
                {
                    case AARCH64_EXT_UXTB:
                        ShiftType = "UXTB";
                        break;
                    case AARCH64_EXT_UXTH:
                        ShiftType = "UXTH";
                        break;
                    case AARCH64_EXT_UXTW:
                        ShiftType = "UXTW";
                        break;
                    case AARCH64_EXT_UXTX:
                        ShiftType = "UXTX";
                        break;
                    case AARCH64_EXT_SXTB:
                        ShiftType = "SXTB";
                        break;
                    case AARCH64_EXT_SXTH:
                        ShiftType = "SXTH";
                        break;
                    case AARCH64_EXT_SXTW:
                        ShiftType = "SXTW";
                        break;
                    case AARCH64_EXT_SXTX:
                        ShiftType = "SXTX";
                        break;
                    case AARCH64_EXT_INVALID:
                        std::cerr << "WARNING: instruction has a non-zero invalid shift at " << Addr
                                  << "\n";
                        return false;
                }
                Facts.Instructions.shiftedOp(
                    relations::ShiftedOp{Addr, rotated_op_index(i + 1, OpCount),
                                         static_cast<uint8_t>(CsOp.shift.value), ShiftType});
            }
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    uint64_t Size(CsInstruction.size);

    Facts.Instructions.add(relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0});
    if(CsInstruction.detail->writeback)
    {
        Facts.Instructions.writeback(relations::InstructionWriteback{Addr});
    }
    return true;
}

std::optional<relations::Operand> Arm64Loader::build(const cs_insn& CsInsn, uint8_t OpIndex,
                                                     const cs_aarch64_op& CsOp)
{
    using namespace relations;

    switch(CsOp.type)
    {
        case AARCH64_OP_REG:
            return RegOp{registerName(CsOp.reg, CsOp.is_vreg)};
        case AARCH64_OP_IMM:
        {
            // ARM64 immediate operands do not have a size.
            relations::ImmOp I = {CsOp.imm, 8};
            return I;
        }
        case AARCH64_OP_MEM:
        {
            int64_t Mult = 1;

            if(CsOp.shift.value != 0)
            {
                // In load and store operations, the only type of shift allowed is LSL.
                if(CsOp.shift.type == AARCH64_SFT_LSL)
                {
                    Mult = 1 << CsOp.shift.value;
                }
                else
                {
                    std::cerr << "WARNING: unsupported shift in indirect op\n";
                }
            }

            IndirectOp I = {registerName(AARCH64_REG_INVALID),
                            registerName(CsOp.mem.base),
                            registerName(CsOp.mem.index),
                            Mult,
                            CsOp.mem.disp,
                            4};
            return I;
        }
        case AARCH64_OP_FP:
            return FPImmOp{CsOp.fp};
        case AARCH64_OP_CIMM:
            std::cerr << "WARNING: unsupported CIMM operand\n";
            break;
        case AARCH64_OP_REG_MRS:
        case AARCH64_OP_REG_MSR:
        case AARCH64_OP_SYSREG:
        case AARCH64_OP_SYSALIAS:
        {
            // Capstone 6 reports system registers, PSTATE fields, barrier
            // options and prefetch operations as system operands.
            if(CsOp.type == AARCH64_OP_SYSALIAS && CsOp.sysop.sub_type == AARCH64_OP_PRFM)
            {
                if(std::optional<const char*> Label = prefetchValue(CsOp.sysop.alias.prfm))
                {
                    return SpecialOp{"prefetch", *Label};
                }
                break;
            }
            switch(capstone_compat::aarch64SystemOperandKind(CsOp))
            {
                case capstone_compat::Aarch64SystemOperand::Pstate:
                {
                    std::optional<std::string> OpString = operandString(CsInsn, OpIndex);
                    if(OpString)
                    {
                        return SpecialOp{"pstate", *OpString};
                    }
                    break;
                }
                case capstone_compat::Aarch64SystemOperand::Barrier:
                {
                    if(std::optional<const char*> Label = barrierValue(CsOp.sysop.alias.db))
                    {
                        return SpecialOp{"barrier", *Label};
                    }
                    break;
                }
                case capstone_compat::Aarch64SystemOperand::Register:
                case capstone_compat::Aarch64SystemOperand::None:
                {
                    // It seems like capstone only has a subset of system registers
                    // implemented for printing with cs_reg_name, so we have to parse
                    // it from the instruction string.
                    std::optional<std::string> Reg = operandString(CsInsn, OpIndex);
                    if(Reg)
                    {
                        return RegOp{*Reg};
                    }
                    break;
                }
            }
            break;
        }
        case AARCH64_OP_INVALID:
        default:
            break;
    }
    std::cerr << "WARNING: unhandled operand at " << CsInsn.address << ", op type:" << CsOp.type
              << "\n";
    return std::nullopt;
}

std::optional<std::string> Arm64Loader::operandString(const cs_insn& CsInsn, uint8_t Index)
{
    // NOTE: assumes commas occur between operands, and neither commas
    // nor spaces occur within them. This is not true of all operand types
    // (e.g., indirect operands). This method should only be used for
    // instructions where this assumption will hold for all its operands.

    uint8_t CurIndex = 0;
    const char* Start = nullptr;
    size_t Size = 0;

    for(const char* Pos = CsInsn.op_str; *Pos != '\0'; Pos++)
    {
        if(*Pos == ',')
        {
            ++CurIndex;
        }
        else if(CurIndex == Index && !isspace(*Pos))
        {
            if(Start == nullptr)
                Start = Pos;

            ++Size;
        }
    }

    if(!Start)
        throw std::logic_error("Operand not found");

    return uppercase(std::string(Start, Size));
}

std::optional<const char*> prefetchValue(const aarch64_prfm Op)
{
    switch(Op)
    {
        case AARCH64_PRFM_PLDL1KEEP:
            return "pldl1keep";
        case AARCH64_PRFM_PLDL1STRM:
            return "pldl1strm";
        case AARCH64_PRFM_PLDL2KEEP:
            return "pldl2keep";
        case AARCH64_PRFM_PLDL2STRM:
            return "pldl2strm";
        case AARCH64_PRFM_PLDL3KEEP:
            return "pldl3keep";
        case AARCH64_PRFM_PLDL3STRM:
            return "pldl3strm";
        case AARCH64_PRFM_PLIL1KEEP:
            return "plil1keep";
        case AARCH64_PRFM_PLIL1STRM:
            return "plil1strm";
        case AARCH64_PRFM_PLIL2KEEP:
            return "plil2keep";
        case AARCH64_PRFM_PLIL2STRM:
            return "plil2strm";
        case AARCH64_PRFM_PLIL3KEEP:
            return "plil3keep";
        case AARCH64_PRFM_PLIL3STRM:
            return "plil3strm";
        case AARCH64_PRFM_PSTL1KEEP:
            return "pstl1keep";
        case AARCH64_PRFM_PSTL1STRM:
            return "pstl1strm";
        case AARCH64_PRFM_PSTL2KEEP:
            return "pstl2keep";
        case AARCH64_PRFM_PSTL2STRM:
            return "pstl2strm";
        case AARCH64_PRFM_PSTL3KEEP:
            return "pstl3keep";
        case AARCH64_PRFM_PSTL3STRM:
            return "pstl3strm";
        default:
            break;
    }
    return std::nullopt;
}

std::optional<const char*> barrierValue(const aarch64_db Op)
{
    switch(Op)
    {
        case AARCH64_DB_OSHLD:
            return "oshld";
        case AARCH64_DB_OSHST:
            return "oshst";
        case AARCH64_DB_OSH:
            return "osh";
        case AARCH64_DB_NSHLD:
            return "nshld";
        case AARCH64_DB_NSHST:
            return "nshst";
        case AARCH64_DB_NSH:
            return "nsh";
        case AARCH64_DB_ISHLD:
            return "ishld";
        case AARCH64_DB_ISHST:
            return "ishst";
        case AARCH64_DB_ISH:
            return "ish";
        case AARCH64_DB_LD:
            return "ld";
        case AARCH64_DB_ST:
            return "st";
        case AARCH64_DB_SY:
            return "sy";
        default:
            break;
    }
    return std::nullopt;
}

std::string Arm64Loader::registerName(unsigned int Reg, bool IsVreg) const
{
    return capstone_compat::aarch64RegisterName(*CsHandle, Reg, IsVreg);
}

void Arm64Loader::registerAccesses(const cs_insn& CsInstruction, std::vector<std::string>& Reads,
                                   std::vector<std::string>& Writes)
{
    cs_regs RegsRead, RegsWrite;
    uint8_t RegsReadCount, RegsWriteCount;
    if(cs_regs_access(*CsHandle, &CsInstruction, RegsRead, &RegsReadCount, RegsWrite,
                      &RegsWriteCount)
       != CS_ERR_OK)
    {
        assert(!"cs_regs_access failed");
        return;
    }
    // Match the register spelling used for vector operands in the facts.
    const cs_aarch64& Details = CsInstruction.detail->aarch64;
    auto isVreg = [&Details](uint16_t Reg) {
        for(uint8_t i = 0; i < Details.op_count; i++)
        {
            const cs_aarch64_op& Op = Details.operands[i];
            if(Op.type == AARCH64_OP_REG && Op.reg == Reg && Op.is_vreg)
            {
                return true;
            }
        }
        return false;
    };
    for(uint8_t i = 0; i < RegsReadCount; i++)
    {
        Reads.push_back(registerName(RegsRead[i], isVreg(RegsRead[i])));
    }
    for(uint8_t i = 0; i < RegsWriteCount; i++)
    {
        Writes.push_back(registerName(RegsWrite[i], isVreg(RegsWrite[i])));
    }
}

uint8_t Arm64Loader::operandCount(const cs_insn& CsInstruction)
{
    const cs_aarch64& Details = CsInstruction.detail->aarch64;
    return Details.op_count;
}

uint8_t Arm64Loader::operandAccess(const cs_insn& CsInstruction, uint64_t Index)
{
    const cs_aarch64& Details = CsInstruction.detail->aarch64;
    const cs_aarch64_op& op = Details.operands[Index];
    return op.access;
}
