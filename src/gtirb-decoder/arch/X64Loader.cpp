//===- X64Loader.cpp -------------------------------------------*- C++ -*-===//
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
//  GNU Affero General Public
//  License for more details.
//
//  This project is sponsored by the Office of Naval Research, One Liberty
//  Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
//  N68335-17-C-0700.  The content of the information does not necessarily
//  reflect the position or policy of the Government and no official
//  endorsement should be inferred.
//
//===----------------------------------------------------------------------===//
#include "X64Loader.h"

#include <algorithm>
#include <string>
#include <vector>

#include "X86Capstone.h"

void X64Loader::decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr)
{
    // Decode instruction with Capstone.
    cs_insn* CsInsn;
    size_t Count = cs_disasm(*CsHandle, Bytes, Size, Addr, 1, &CsInsn);

    // Build datalog instruction facts from Capstone instruction.
    std::optional<relations::Instruction> Instruction;
    if(Count > 0 && !isInvalidX64Encoding(*CsInsn))
    {
        Instruction = build(Facts, *CsInsn);
    }

    if(Instruction)
    {
        // Add the instruction to the facts table.
        Facts.Instructions.add(*Instruction);
        loadRegisterAccesses(Facts, Addr, *CsInsn);
        loadVectorAccesses(Facts, *CsInsn);
        loadFlagAccesses(Facts, *CsInsn);
    }
    else
    {
        // Add address to list of invalid instruction locations.
        Facts.Instructions.invalid(gtirb::Addr(Addr));
    }

    cs_free(CsInsn, Count);
}

std::optional<relations::Instruction> X64Loader::build(BinaryFacts& Facts,
                                                       const cs_insn& CsInstruction)
{
    cs_x86& Details = CsInstruction.detail->x86;
    auto [Prefix, Name] = splitMnemonic(CsInstruction);
    std::vector<uint64_t> OpCodes;

    if(Name != "NOP")
    {
        int OpCount = Details.op_count;
        for(int i = 0; i < OpCount; i++)
        {
            // Load capstone operand.
            cs_x86_op& CsOp = Details.operands[i];

            // Build operand for datalog fact.
            std::optional<relations::Operand> Op = build(CsOp);
            if(!Op)
            {
                return std::nullopt;
            }

            // Add operand to the operands table.
            uint64_t OpIndex = Facts.Operands.add(*Op);
            OpCodes.push_back(OpIndex);
        }
        // Put the destination operand at the end of the operand list.
        if(OpCount > 0)
        {
            std::rotate(OpCodes.begin(), OpCodes.begin() + 1, OpCodes.end());
        }
    }

    gtirb::Addr Addr(CsInstruction.address);
    uint64_t Size(CsInstruction.size);
    uint8_t Imm(Details.encoding.imm_offset), Disp(Details.encoding.disp_offset);
    return relations::Instruction{Addr, Size, Prefix, Name, OpCodes, Imm, Disp};
}

std::tuple<std::string, std::string> X64Loader::splitMnemonic(const cs_insn& CsInstruction)
{
    std::string PrefixName = uppercase(CsInstruction.mnemonic);
    std::string Prefix, Name;
    size_t Pos = PrefixName.find(' ');
    if(Pos != std::string::npos)
    {
        Prefix = PrefixName.substr(0, Pos);
        Name = PrefixName.substr(Pos + 1);
    }
    else
    {
        Prefix = "";
        Name = PrefixName;
    }
    return {Prefix, Name};
}

std::optional<relations::Operand> X64Loader::build(const cs_x86_op& CsOp)
{
    auto registerName = [this](unsigned int Reg) {
        return (Reg == X86_REG_INVALID) ? "NONE" : uppercase(cs_reg_name(*CsHandle, Reg));
    };

    switch(CsOp.type)
    {
        case X86_OP_REG:
            return registerName(CsOp.reg);
        case X86_OP_IMM:
        {
            relations::ImmOp I = {CsOp.imm, CsOp.size};
            return I;
        }
        case X86_OP_MEM:
        {
            relations::IndirectOp I = {registerName(CsOp.mem.segment),
                                       registerName(CsOp.mem.base),
                                       registerName(CsOp.mem.index),
                                       CsOp.mem.scale,
                                       CsOp.mem.disp,
                                       CsOp.size};
            return I;
        }
        case X86_OP_INVALID:
        default:
            break;
    }
    return std::nullopt;
}

uint8_t X64Loader::operandCount(const cs_insn& CsInstruction)
{
    const cs_x86& Details = CsInstruction.detail->x86;
    return Details.op_count;
}

uint8_t X64Loader::operandAccess(const cs_insn& CsInstruction, uint64_t Index)
{
    const cs_x86& Details = CsInstruction.detail->x86;
    const cs_x86_op& op = Details.operands[Index];
    return op.access;
}

void X64Loader::registerAccesses(const cs_insn& CsInstruction, std::vector<std::string>& Reads,
                                 std::vector<std::string>& Writes)
{
    InstructionLoader::registerAccesses(CsInstruction, Reads, Writes);
    fixX86Capstone6Accesses(CsInstruction, Reads, Writes);
}

void X64Loader::loadVectorAccesses(BinaryFacts& Facts, const cs_insn& Insn)
{
    const auto &X = Insn.detail->x86;
    auto [Prefix, Op] = splitMnemonic(Insn);
    auto IsVector = [](unsigned Reg) {
        return (Reg >= X86_REG_XMM0 && Reg <= X86_REG_ZMM31)
               || (Reg >= X86_REG_K0 && Reg <= X86_REG_K7);
    };
    bool HasVectorOperand = false;
    for(unsigned I = 0; I < X.op_count; ++I)
        HasVectorOperand |= (X.operands[I].type == X86_OP_REG && IsVector(X.operands[I].reg))
                            || (X.operands[I].type == X86_OP_MEM && IsVector(X.operands[I].mem.index));
    // Avoid a second native access query on ordinary GPR instructions. These
    // two zeroing instructions have no operands but implicit vector writes.
    if(!HasVectorOperand && Op != "VZEROUPPER" && Op != "VZEROALL") return;
    // VEX/EVEX may follow address-size/segment prefixes. The opcode bytes in
    // Capstone's detail omit legacy prefixes and retain the vector prefix.
    bool VectorEncoding = X.opcode[0] == 0xc4 || X.opcode[0] == 0xc5 || X.opcode[0] == 0x62;
    bool Masked = false, ZeroMask = false;
    for(unsigned I = 0; I < X.op_count; ++I)
    {
        const auto &Operand = X.operands[I];
        Masked |= Operand.type == X86_OP_REG && Operand.reg >= X86_REG_K1
                  && Operand.reg <= X86_REG_K7;
        ZeroMask |= Operand.avx_zero_opmask;
    }
    // An explicit predicate operand is distinct from a k-register instruction.
    Masked &= X.op_count && X.operands[0].type == X86_OP_REG
              && X.operands[0].reg >= X86_REG_XMM0;
    std::string ZeroSource;
    bool ZeroIdiom = Op == "PXOR" || Op == "XORPS" || Op == "XORPD"
                     || Op == "PSUBB" || Op == "PSUBW" || Op == "PSUBD" || Op == "PSUBQ"
                     || Op == "VPXOR" || Op == "VPXORD" || Op == "VPXORQ"
                     || Op == "VXORPS" || Op == "VXORPD"
                     || Op == "VPSUBB" || Op == "VPSUBW" || Op == "VPSUBD" || Op == "VPSUBQ"
                     || Op == "KXORB" || Op == "KXORW" || Op == "KXORD" || Op == "KXORQ";
    // Ignore opmask operands when locating the two data sources.
    std::vector<unsigned> DataRegisters;
    for(unsigned I = 0; I < X.op_count; ++I)
        if(X.operands[I].type == X86_OP_REG
           && ((X.operands[I].reg >= X86_REG_XMM0 && X.operands[I].reg <= X86_REG_ZMM31)
               || (Op[0] == 'K' && X.operands[I].reg >= X86_REG_K0 && X.operands[I].reg <= X86_REG_K7)))
            DataRegisters.push_back(X.operands[I].reg);
    unsigned Required = VectorEncoding ? 3 : 2;
    if(ZeroIdiom && DataRegisters.size() == Required
       && DataRegisters[Required - 1] == DataRegisters[Required - 2])
        ZeroSource = uppercase(cs_reg_name(*CsHandle, DataRegisters.back()));

    auto Access = [&](const std::string &Reg, const char *Mode) {
        Facts.Instructions.vectorAccess({gtirb::Addr(Insn.address), Mode, Reg});
    };
    auto Pieces = [](const std::string &Reg) {
        std::vector<std::string> Result;
        if(Reg.size() > 3 && (Reg.substr(0,3) == "XMM" || Reg.substr(0,3) == "YMM"
                             || Reg.substr(0,3) == "ZMM"))
        {
            auto N = Reg.substr(3);
            Result.push_back("XMM" + N);
            if(Reg[0] != 'X') Result.push_back("YMM" + N + "H");
            if(Reg[0] == 'Z') Result.push_back("ZMM" + N + "H");
        }
        else if(Reg.size() == 2 && Reg[0] == 'K' && Reg[1] >= '0' && Reg[1] <= '7')
            Result.push_back(Reg);
        return Result;
    };
    std::vector<std::string> Reads, Writes;
    registerAccesses(Insn, Reads, Writes);
    for(const auto &Reg : Reads)
        if(Reg != ZeroSource)
            for(const auto &Piece : Pieces(Reg)) Access(Piece, "R");
    for(const auto &Reg : Writes)
    {
        auto Parts = Pieces(Reg);
        if(Parts.empty()) continue;
        bool Xmm = Reg.substr(0,3) == "XMM";
        // Legacy scalar/insert forms can leave part of the low 128 bits intact.
        // Even when Capstone omits that destination read, retain the low piece.
        bool Partial = !VectorEncoding && Xmm
            && ((Op.size() >= 2 && (Op.substr(Op.size()-2) == "SS" || Op.substr(Op.size()-2) == "SD"))
                || Op.find("PINSR") == 0 || Op == "INSERTPS" || Op == "MOVLPS"
                || Op == "MOVLPD" || Op == "MOVHPS" || Op == "MOVHPD"
                || Op == "MOVLHPS" || Op == "MOVHLPS");
        Partial |= Op.find("GATHER") != std::string::npos;
        bool MemorySource = X.op_count > 1 && X.operands[1].type == X86_OP_MEM;
        if((Op == "MOVSS" || Op == "MOVSD") && MemorySource) Partial = false;
        for(const auto &Piece : Parts)
        {
            Access(Piece, "W");
            if(Partial || (Masked && !ZeroMask)) Access(Piece, "R");
        }
        // VEX/EVEX zero all bits above the destination's encoded vector length,
        // independently of merging writemasks below that length.
        if(VectorEncoding && Reg.size() > 3 && Reg[1] == 'M')
        {
            auto N = Reg.substr(3);
            if(Xmm) Access("YMM" + N + "H", "W");
            if(Reg[0] != 'Z') Access("ZMM" + N + "H", "W");
        }
    }
    // These have implicit definitions which cs_regs_access does not enumerate.
    if(Op == "VZEROUPPER" || Op == "VZEROALL")
        for(unsigned I = 0; I < 16; ++I)
        {
            auto N = std::to_string(I);
            Access("YMM" + N + "H", "W");
            Access("ZMM" + N + "H", "W");
            if(Op == "VZEROALL") Access("XMM" + N, "W");
        }
}

void X64Loader::loadFlagAccesses(BinaryFacts& Facts, const cs_insn& Insn)
{
    // Capstone's per-flag read (TEST, PRIOR) and write (MODIFY, RESET, SET,
    // UNDEFINED) bits. An undefined result replaces the flag's value too.
    struct Flag
    {
        const char* Name;
        uint64_t Read, Write;
    };
    static const Flag Flags[] = {
        {"CF", X86_EFLAGS_TEST_CF | X86_EFLAGS_PRIOR_CF,
         X86_EFLAGS_MODIFY_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_UNDEFINED_CF},
        {"PF", X86_EFLAGS_TEST_PF | X86_EFLAGS_PRIOR_PF,
         X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_UNDEFINED_PF},
        {"AF", X86_EFLAGS_TEST_AF | X86_EFLAGS_PRIOR_AF,
         X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_AF},
        {"ZF", X86_EFLAGS_TEST_ZF | X86_EFLAGS_PRIOR_ZF,
         X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_UNDEFINED_ZF},
        {"SF", X86_EFLAGS_TEST_SF | X86_EFLAGS_PRIOR_SF,
         X86_EFLAGS_MODIFY_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_UNDEFINED_SF},
        {"OF", X86_EFLAGS_TEST_OF | X86_EFLAGS_PRIOR_OF,
         X86_EFLAGS_MODIFY_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_UNDEFINED_OF},
    };
    const unsigned All = 63, CF = 1, PF = 2, ZF = 8, OF = 32;
    const uint64_t UntrackedReads = X86_EFLAGS_TEST_TF | X86_EFLAGS_PRIOR_TF | X86_EFLAGS_TEST_IF
                                    | X86_EFLAGS_PRIOR_IF | X86_EFLAGS_TEST_DF | X86_EFLAGS_PRIOR_DF
                                    | X86_EFLAGS_TEST_NT | X86_EFLAGS_PRIOR_NT | X86_EFLAGS_TEST_RF;
    const cs_x86& X = Insn.detail->x86;
    const std::string Op = std::get<1>(splitMnemonic(Insn));
    unsigned Read = 0, Write = 0;
    cs_regs RegsRead, RegsWrite;
    uint8_t ReadCount, WriteCount;
    if(cs_insn_group(*CsHandle, &Insn, CS_GRP_INT))
    {
        Read = All;
    }
    // Capstone 6.0.0-Alpha11 omits FCMOV's flag reads. Its eflags field is
    // then fpu_flags, which share a union, and must not be read as flags.
    else if(Op == "FCMOVB" || Op == "FCMOVNB")
        Read = CF;
    else if(Op == "FCMOVE" || Op == "FCMOVNE")
        Read = ZF;
    else if(Op == "FCMOVBE" || Op == "FCMOVNBE")
        Read = CF | ZF;
    else if(Op == "FCMOVU" || Op == "FCMOVNU")
        Read = PF;
    else if(cs_regs_access(*CsHandle, &Insn, RegsRead, &ReadCount, RegsWrite, &WriteCount)
            != CS_ERR_OK)
    {
        Read = All;
    }
    else
    {
        // These consume the carry even where Capstone omits the read.
        if(Op == "RCL" || Op == "RCR" || Op == "CMC")
            Read = CF;
        bool FlagsRead = std::find(RegsRead, RegsRead + ReadCount, X86_REG_EFLAGS)
                         != RegsRead + ReadCount;
        bool FlagsWritten = std::find(RegsWrite, RegsWrite + WriteCount, X86_REG_EFLAGS)
                            != RegsWrite + WriteCount;
        // Only an instruction that accesses the flags register has eflags;
        // x87 status operations store fpu_flags in the same field.
        if(FlagsRead || FlagsWritten)
        {
            for(unsigned I = 0; I < 6; ++I)
            {
                if(X.eflags & Flags[I].Read)
                    Read |= 1u << I;
                if(X.eflags & Flags[I].Write)
                    Write |= 1u << I;
            }
            // Alpha11 marks LAHF's flags read but leaves eflags zero. ADOX
            // similarly lists a flags read but only an OF write in eflags.
            // A flags read with no per-flag bits reads all of them, unless it
            // reads only an untracked flag such as DF.
            if(Op == "LAHF")
                Read = All & ~OF;
            else if(!Read && !(X.eflags & UntrackedReads) && FlagsRead)
                Read = All;
            // A shift or rotate by a register, or by a masked count of zero,
            // leaves the flags unchanged.
            if((Op == "SHL" || Op == "SAL" || Op == "SHR" || Op == "SAR" || Op == "SHLD"
                || Op == "SHRD" || Op == "ROL" || Op == "ROR" || Op == "RCL" || Op == "RCR")
               && X.op_count > 0)
            {
                const cs_x86_op& Count = X.operands[X.op_count - 1];
                const unsigned Width = X.operands[0].size * 8;
                if(Count.type != X86_OP_IMM)
                {
                    Write = 0;
                }
                else
                {
                    uint64_t Effective = static_cast<uint64_t>(Count.imm) & (Width == 64 ? 63 : 31);
                    if((Op == "ROL" || Op == "ROR") && Width)
                        Effective %= Width;
                    else if((Op == "RCL" || Op == "RCR") && Width && Width < 32)
                        Effective %= Width + 1;
                    if(Effective == 0)
                        Write = 0;
                }
            }
        }
    }
    for(unsigned I = 0; I < 6; ++I)
    {
        if(Read & (1u << I))
            Facts.Instructions.flagAccess({gtirb::Addr(Insn.address), "R", Flags[I].Name});
        if(Write & (1u << I))
            Facts.Instructions.flagAccess({gtirb::Addr(Insn.address), "W", Flags[I].Name});
    }
}
