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

#endif // SRC_GTIRB_DECODER_ARCH_X86CAPSTONE_H_
