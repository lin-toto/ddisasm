//===- Arm64Capstone.h ------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_ARM64CAPSTONE_H_
#define SRC_GTIRB_DECODER_ARCH_ARM64CAPSTONE_H_

#include <capstone/capstone.h>

// Corrections for verified Capstone 6.0.0-Alpha11 errors only. All other
// operand and register accesses come directly from the current decoder.
inline void fixAArch64Capstone6Accesses(cs_insn& Insn)
{
    auto& Detail = *Insn.detail;
    auto& A = Detail.aarch64;
    switch(Insn.id)
    {
        case AARCH64_INS_CAS:
        case AARCH64_INS_CASA:
        case AARCH64_INS_CASAL:
        case AARCH64_INS_CASL:
        case AARCH64_INS_CASB:
        case AARCH64_INS_CASAB:
        case AARCH64_INS_CASALB:
        case AARCH64_INS_CASLB:
        case AARCH64_INS_CASH:
        case AARCH64_INS_CASAH:
        case AARCH64_INS_CASALH:
        case AARCH64_INS_CASLH:
        case AARCH64_INS_CASP:
        case AARCH64_INS_CASPA:
        case AARCH64_INS_CASPAL:
        case AARCH64_INS_CASPL:
            // Alpha11 marks the tied compare/result as read-only for CAS,
            // and reports base writeback for both CAS and CASP. Neither
            // instruction updates its address register. CAS also includes
            // the spurious base in its implicit write list. Neither family
            // has implicit register writes. CASP's two explicit
            // result operands already have their correct read/write access.
            Detail.writeback = false;
            Detail.regs_write_count = 0;
            if(A.op_count && A.operands[0].type == AARCH64_OP_REG)
            {
                A.operands[0].access = CS_AC_READ_WRITE;
            }
            break;
        case AARCH64_INS_SWP:
        case AARCH64_INS_SWPA:
        case AARCH64_INS_SWPAL:
        case AARCH64_INS_SWPL:
        case AARCH64_INS_SWPB:
        case AARCH64_INS_SWPAB:
        case AARCH64_INS_SWPALB:
        case AARCH64_INS_SWPLB:
        case AARCH64_INS_SWPH:
        case AARCH64_INS_SWPAH:
        case AARCH64_INS_SWPALH:
        case AARCH64_INS_SWPLH:
            // Alpha11 omits the memory access on the atomic swap family.
            // SWP reads the old memory value and stores the source register;
            // its explicit register accesses are already correct.
            for(unsigned I = 0; I < A.op_count; ++I)
                if(A.operands[I].type == AARCH64_OP_MEM)
                    A.operands[I].access = CS_AC_READ_WRITE;
            break;
        default:
            break;
    }
}

#endif // SRC_GTIRB_DECODER_ARCH_ARM64CAPSTONE_H_
