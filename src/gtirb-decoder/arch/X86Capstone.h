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

// Capstone 6.0.0-Alpha11 reports AL instead of the implicit EDX:EAX and
// ECX:EBX (RDX:RAX and RCX:RBX) pairs of CMPXCHG8B/16B. The pairs are read,
// EDX:EAX (RDX:RAX) and RFLAGS are written, and address registers are read.
// Keep the decoder's accesses for every other instruction, including its
// program-counter and segment-register facts; analyses choose what to track.
inline void fixX86Capstone6Accesses(const cs_insn& CsInstruction, std::vector<std::string>& Reads,
                                   std::vector<std::string>& Writes)
{
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

// Alpha11 incorrectly decodes REX directly before VEX (C4/C5) or EVEX (62).
// The CPU raises #UD for these encodings. Do not reject valid instructions
// merely because an older decoder did not support them.
inline bool isInvalidX64Encoding(const cs_insn& CsInstruction)
{
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
