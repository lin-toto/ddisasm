//===- X86Capstone.h --------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_X86CAPSTONE_H_
#define SRC_GTIRB_DECODER_ARCH_X86CAPSTONE_H_

#include <capstone/capstone.h>

#include <algorithm>
#include <initializer_list>
#include <string>
#include <vector>

// Corrections to Capstone 6's x86 output for the x86 loaders.

// Correct the x86 register accesses Capstone 6 reports where they differ from
// what the x86 analyses were written against (Capstone 5.0.1) in a way that
// matters to them:
//
// - The program counter (RIP, EIP, IP) and the CS, DS, ES and SS segment
//   registers are dropped. Capstone 6 reports RIP as written by every call,
//   jump and return and as read by every jump, and SS as read by every
//   return; it no longer reports CS/DS/ES/SS segment overrides, which
//   Capstone 5 listed as reads. The analyses track none of these registers:
//   the program counter is only used through PC-relative operands, and
//   these segments are flat (base 0). FS and GS, which address thread-local
//   storage, are kept.
// - CMPXCHG8B and CMPXCHG16B: Capstone 6.0.0-Alpha11 reports AL instead of
//   the implicit EDX:EAX and ECX:EBX (RDX:RAX and RCX:RBX) pairs. They get
//   Capstone 5's sets back: the pairs are read, EDX:EAX (RDX:RAX) and RFLAGS
//   are written, and the memory operand's registers are still read.
//
// Everything else Capstone 6 reports is kept; where it differs from
// Capstone 5 it is a correction (for example SYSCALL now writes RCX, R11
// and RFLAGS, and string instructions name RSI/RDI rather than ESI/EDI).
inline void fixX86RegisterAccesses(const cs_insn& CsInstruction, std::vector<std::string>& Reads,
                                   std::vector<std::string>& Writes)
{
    auto Untracked = [](const std::string& Reg) {
        return Reg == "RIP" || Reg == "EIP" || Reg == "IP" || Reg == "CS" || Reg == "DS"
               || Reg == "ES" || Reg == "SS";
    };
    Reads.erase(std::remove_if(Reads.begin(), Reads.end(), Untracked), Reads.end());
    Writes.erase(std::remove_if(Writes.begin(), Writes.end(), Untracked), Writes.end());

    if(CsInstruction.id == X86_INS_CMPXCHG8B || CsInstruction.id == X86_INS_CMPXCHG16B)
    {
        const bool Wide = CsInstruction.id == X86_INS_CMPXCHG16B;
        auto Add = [](std::vector<std::string>& Regs, std::initializer_list<const char*> Names) {
            for(const char* Name : Names)
            {
                if(std::find(Regs.begin(), Regs.end(), Name) == Regs.end())
                {
                    Regs.push_back(Name);
                }
            }
        };
        Reads.erase(std::remove(Reads.begin(), Reads.end(), "AL"), Reads.end());
        Writes.clear();
        if(Wide)
        {
            Add(Reads, {"RAX", "RBX", "RCX", "RDX"});
            Add(Writes, {"RAX", "RDX", "RFLAGS"});
        }
        else
        {
            Add(Reads, {"EAX", "EBX", "ECX", "EDX"});
            Add(Writes, {"EAX", "EDX", "RFLAGS"});
        }
    }
}

// Capstone 6 decodes a few x86-64 encodings that Capstone 5.0.1 rejected. The
// x86-64 loader reports them as invalid, so the disassembly weighs the same
// instruction candidates as before (the loader decodes at every byte offset):
//
// - MOVSXD without REX.W (63 /r with a 16- or 32-bit destination). The form is
//   valid but discouraged, compilers do not emit it, and Capstone 5.0.1
//   treated it as invalid.
// - A REX prefix directly before a VEX (C4/C5) or EVEX (62) prefix. The CPU
//   raises #UD for such an instruction, but Capstone 6 decodes it.
//
// Measured over every byte offset of test_fuzz, libz.so and bash, these are
// all the encodings Capstone 6 accepts and Capstone 5.0.1 rejects. (The one
// encoding in the other direction, LOCK MOVDQU, is invalid and Capstone 6 is
// right to reject it.)
inline bool isX64EncodingCapstone5Rejected(const cs_insn& CsInstruction)
{
    if(CsInstruction.id == X86_INS_MOVSXD && (CsInstruction.detail->x86.rex & 0x08) == 0)
    {
        return true;
    }
    uint16_t I = 0;
    auto isLegacyPrefix = [](uint8_t B) {
        return B == 0xF0 || B == 0xF2 || B == 0xF3 || B == 0x2E || B == 0x36 || B == 0x3E
               || B == 0x26 || B == 0x64 || B == 0x65 || B == 0x66 || B == 0x67;
    };
    while(I < CsInstruction.size && isLegacyPrefix(CsInstruction.bytes[I]))
    {
        ++I;
    }
    const uint16_t RexStart = I;
    while(I < CsInstruction.size && (CsInstruction.bytes[I] & 0xF0) == 0x40)
    {
        ++I;
    }
    if(I == RexStart || I >= CsInstruction.size)
    {
        return false;
    }
    const uint8_t Next = CsInstruction.bytes[I];
    return Next == 0xC4 || Next == 0xC5 || Next == 0x62;
}

#endif // SRC_GTIRB_DECODER_ARCH_X86CAPSTONE_H_
