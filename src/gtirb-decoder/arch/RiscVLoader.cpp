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

namespace
{
bool isCompressedLoad(const std::string& Name)
{
    return Name == "C.LW" || Name == "C.LWSP" || Name == "C.LD" || Name == "C.LDSP"
           || Name == "C.FLW" || Name == "C.FLWSP" || Name == "C.FLD" || Name == "C.FLDSP";
}

bool isCompressedStore(const std::string& Name)
{
    return Name == "C.SW" || Name == "C.SWSP" || Name == "C.SD" || Name == "C.SDSP"
           || Name == "C.FSW" || Name == "C.FSWSP" || Name == "C.FSD" || Name == "C.FSDSP";
}
} // namespace

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

    // Build datalog instruction facts from Capstone instruction. The adapter
    // rewrites Capstone 6's output into the shape Capstone 5.0.1 produced and
    // rejects what Capstone 5.0.1 did not decode, which is then treated as a
    // failed decode.
    std::optional<relations::Instruction> Instruction;
    uint64_t InstructionSize = MinInstructionSize;
    if(Count > 0 && capstone_compat::adaptRiscv(*CsHandle, *CsInsn))
    {
        Instruction = build(Facts, *CsInsn);
        InstructionSize = CsInsn->size;
    }

    if(Instruction)
    {
        Facts.Instructions.add(*Instruction);

        // Capstone 5.0.1 does not provide RISC-V operand access metadata.
        // Accesses are modeled in datalog, like MIPS.
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

    if((Name == "JAL" || Name == "JALR") && Details.op_count > 0
       && Details.operands[0].type == RISCV_OP_REG && Details.operands[0].reg == RISCV_REG_X0)
    {
        Name = (Name == "JAL") ? "J" : "JR";
    }

    if(Name != "NOP" && Name != "C.NOP")
    {
        int OpCount = Details.op_count;
        if((isCompressedLoad(Name) || isCompressedStore(Name)) && OpCount == 3
           && Details.operands[0].type == RISCV_OP_REG
           && Details.operands[1].type == RISCV_OP_IMM
           && Details.operands[2].type == RISCV_OP_REG)
        {
            using namespace relations;

            const cs_riscv_op& RegOp = Details.operands[0];
            const cs_riscv_op& DispOp = Details.operands[1];
            const cs_riscv_op& BaseOp = Details.operands[2];

            IndirectOp MemOp{registerName(RISCV_REG_INVALID),
                             registerName(BaseOp.reg),
                             registerName(RISCV_REG_INVALID),
                             1,
                             DispOp.imm,
                             memoryAccessSize(Name)};
            OpCodes.push_back(Facts.Operands.add(MemOp));
            OpCodes.push_back(Facts.Operands.add(relations::RegOp{registerName(RegOp.reg)}));
        }
        else
        {
            for(int i = 0; i < OpCount; i++)
            {
                const cs_riscv_op& CsOp = Details.operands[i];

                std::optional<relations::Operand> Op = build(CsOp, Name);
                if(!Op)
                {
                    return std::nullopt;
                }

                uint64_t OpIndex = Facts.Operands.add(*Op);
                OpCodes.push_back(OpIndex);
            }

            // Put the destination operand at the end of the operand list.
            if(OpCount > 0)
            {
                std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
            }
        }
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

uint8_t RiscVLoader::operandAccess(const cs_insn&, uint64_t)
{
    // RISC-V does not provide operand access information in Capstone 5.0.1.
    return CS_AC_INVALID;
}
