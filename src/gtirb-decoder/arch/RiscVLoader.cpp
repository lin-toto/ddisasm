//===- RiscVLoader.cpp -----------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
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
//===----------------------------------------------------------------------===//
#include "RiscVLoader.h"

#include <algorithm>
#include <string>
#include <vector>

void RiscVLoader::load(const gtirb::Module&, const gtirb::ByteInterval& ByteInterval,
                       BinaryFacts& Facts)
{
    assert(ByteInterval.getAddress() && "ByteInterval is non-addressable.");

    uint64_t Addr = static_cast<uint64_t>(*ByteInterval.getAddress());
    uint64_t Size = ByteInterval.getInitializedSize();
    auto Data = ByteInterval.rawBytes<const uint8_t>();

    while(Size >= MinInstructionSize)
    {
        uint64_t InstructionSize = decodeInstruction(Facts, Data, Size, Addr);
        Addr += InstructionSize;
        Data += InstructionSize;
        Size -= InstructionSize;
    }
}

void RiscVLoader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    decodeInstruction(Facts, Bytes, Size, Addr);
}

uint64_t RiscVLoader::decodeInstruction(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size,
                                        uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Consume native real-instruction details, including CSR operands,
    // absolute branch targets and compressed memory operands.
    std::optional<relations::Instruction> Instruction;
    uint64_t InstructionSize = MinInstructionSize;
    if(Count > 0)
    {
        Instruction = build(Facts, *CsInsn);
        InstructionSize = CsInsn->size;
    }

    if(Instruction)
    {
        Facts.Instructions.add(*Instruction);

        loadRegisterAccesses(Facts, Addr, *CsInsn);
    }
    else
    {
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
    return InstructionSize;
}

std::optional<relations::Instruction> RiscVLoader::build(BinaryFacts& Facts,
                                                         const cs_insn& CsInstruction)
{
    const cs_riscv& Details = CsInstruction.detail->riscv;
    std::string Name = uppercase(CsInstruction.mnemonic);
    std::vector<uint64_t> OpCodes;

    for(int i = 0; i < Details.op_count; i++)
    {
        std::optional<relations::Operand> Op = build(Details.operands[i], Name);
        if(!Op)
        {
            return std::nullopt;
        }
        OpCodes.push_back(Facts.Operands.add(*Op));
    }
    // The fact schema puts the first printed operand last on every ISA.
    if(!OpCodes.empty())
    {
        std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    return relations::Instruction{Addr, Size, "", Name, OpCodes, 0, 0};
}

std::optional<relations::Operand> RiscVLoader::build(const cs_riscv_op& CsOp,
                                                     const std::string& Name)
{
    using namespace relations;

    switch(CsOp.type)
    {
        case RISCV_OP_REG:
            return RegOp{registerName(CsOp.reg)};
        case RISCV_OP_IMM:
            return ImmOp{CsOp.imm, PointerSize};
        case RISCV_OP_CSR:
            return SpecialOp{"CSR", std::to_string(CsOp.csr)};
        case RISCV_OP_FP:
            return FPImmOp{CsOp.dimm};
        case RISCV_OP_MEM:
            return IndirectOp{registerName(RISCV_REG_INVALID),
                              registerName(CsOp.mem.base),
                              registerName(RISCV_REG_INVALID),
                              1,
                              CsOp.mem.disp,
                              memoryAccessSize(Name)};
        case RISCV_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

std::string RiscVLoader::registerName(unsigned int Reg) const
{
    return (Reg == RISCV_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
}

uint8_t RiscVLoader::memoryAccessSize(const std::string& Name) const
{
    // Acquire/release ordering suffixes do not change an atomic's data width.
    auto Dot = Name.rfind('.');
    if(Dot != std::string::npos)
    {
        const auto Suffix = Name.substr(Dot);
        if(Suffix == ".AQ" || Suffix == ".RL" || Suffix == ".AQRL")
            return memoryAccessSize(Name.substr(0, Dot));
    }
    if(Name == "LB" || Name == "LBU" || Name == "SB")
    {
        return 1;
    }
    if(Name == "LH" || Name == "LHU" || Name == "SH")
    {
        return 2;
    }
    if(Name == "LW" || Name == "LWU" || Name == "SW" || Name == "FLW" || Name == "FSW"
       || Name == "C.LW" || Name == "C.LWSP" || Name == "C.SW" || Name == "C.SWSP"
       || Name == "C.FLW" || Name == "C.FLWSP" || Name == "C.FSW" || Name == "C.FSWSP")
    {
        return 4;
    }
    if(Name == "LD" || Name == "SD" || Name == "FLD" || Name == "FSD" || Name == "C.LD"
       || Name == "C.LDSP" || Name == "C.SD" || Name == "C.SDSP" || Name == "C.FLD"
       || Name == "C.FLDSP" || Name == "C.FSD" || Name == "C.FSDSP")
    {
        return 8;
    }
    if(Name == "LQ" || Name == "SQ")
    {
        return 16;
    }
    if(Name.size() >= 2 && Name.compare(Name.size() - 2, 2, ".W") == 0)
    {
        return 4;
    }
    if(Name.size() >= 2 && Name.compare(Name.size() - 2, 2, ".D") == 0)
    {
        return 8;
    }
    return PointerSize;
}

uint8_t RiscVLoader::operandCount(const cs_insn& CsInstruction)
{
    const cs_riscv& Details = CsInstruction.detail->riscv;
    return Details.op_count;
}

uint8_t RiscVLoader::operandAccess(const cs_insn& CsInstruction, uint64_t Index)
{
    const auto& Op = CsInstruction.detail->riscv.operands[Index];
    // Alpha11 marks SC's memory operand read/write. SC writes conditionally;
    // unlike an AMO, it does not load the previous memory value.
    if(Op.type == RISCV_OP_MEM && std::string(CsInstruction.mnemonic).rfind("sc.", 0) == 0)
        return CS_AC_WRITE;
    return Op.access;
}

void RiscVLoader::registerAccesses(const cs_insn& CsInstruction,
                                  std::vector<std::string>& Reads,
                                  std::vector<std::string>& Writes)
{
    InstructionLoader::registerAccesses(CsInstruction, Reads, Writes);
    // Alpha11's RISCV_reg_access only visits explicit operands. These two
    // compressed calls have an implicit link-register result.
    if(CsInstruction.id == RISCV_INS_C_JAL || CsInstruction.id == RISCV_INS_C_JALR)
        Writes.push_back(registerName(RISCV_REG_X1));
}
