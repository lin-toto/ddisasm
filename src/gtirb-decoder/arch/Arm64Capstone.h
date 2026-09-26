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

#include <cstdint>
#include <cstring>

// Capstone 5.0.1's AArch64 register accesses, recreated on a Capstone 6
// instruction that capstone_compat::adaptAArch64 has already reshaped.
//
// The AArch64 analyses (def-use, live registers, and the corrections in
// arch/arm64/registers.dl) were written against Capstone 5's access
// information. Capstone 6 fixes many of its errors, but taking the fixes
// changes which registers the live-register analysis reports as free, which
// is a separate, reviewed change. Until then the loader recreates Capstone 5's
// answer for the registers the analyses track (X0-X30, SP and NZCV) by
// changing the operand access and the implicit register lists that
// cs_regs_access and operandAccess read. Each rule is a Capstone 5 behaviour
// measured by decoding the same bytes with both versions (libc.so, libm.so,
// test_fuzz, 2M random words):
//
//  A. CMP, CMN and TST mark their first operand written and not read.
//  B. CBZ and CBNZ read NZCV.
//  C. RET, RETAA and RETAB do not read X30 (see capstone5RegsAccess).
//  D. SVC writes X30.
//  E. SBFM and UBFM (asr, lsl, lsr, sbfiz, sbfx, sxtb, sxth, sxtw, ubfiz,
//     ubfx, uxtb, uxth) also read their destination.
//  F. DC, IC, AT and TLBI give their register operand no access; SYSL reads
//     its destination as well.
//  G. ADDS with a 32-bit first operand and an immediate (so also CMN) reads
//     the first operand and does not write it.
//  H. CAS, CASP, SWP and the LD<op>/ST<op> atomics have no operand access and
//     no implicit registers: only the address register is read.
//  I. SCVTF, UCVTF, FCVTZS and FCVTZU with a half-precision operand have no
//     access information.
//
// Capstone 5's access for the other operand kinds is recreated too, because
// instruction_get_src_op and instruction_get_dest_op feed the data-access,
// stack-variable and value analyses:
//
//  J. The memory operand of the STR, STUR, STP, STNP and STTR families is
//     read and written; that of STLR* and of the exclusive loads and stores
//     (LDXR, LDAXR, STXR, STLXR, their pair and byte/halfword forms) is read.
//  K. The memory operand of an LDR/LDP-family load with base writeback, and of
//     PRFM/PRFUM, is read and written (LDR: see the form table in the code).
//  L. The immediate of MOVZ, MOVN and ORR printed as MOV, of UDF and of the
//     SIMD compares with zero has no access.
//  M. The system register of MRS is read and that of MSR written.
//  N. The barrier option of DMB and DSB is read.
//  O. The #0.0 of FCMP/FCMPE has no access, the flags immediate of
//     FCCMP/FCCMPE is written, and the destination of FMOV (immediate), MVNI
//     and the vector SSHR/USHR/URSHR is read and written.
//  P. No instruction lists FPCR (see capstone5RegsAccess).
//  Q. The NEON structure loads and stores (LD1-LD4, LD1R-LD4R, ST1-ST4) get
//     Capstone 5's access list, a short per-form list applied to the first
//     operands, so the post-increment register of most forms has no access
//     (see the LD1-ST4 case below).
//
// All rules but C and P are applied to the instruction by
// emulateCapstone5Access, before anything reads it; C and P are applied by
// capstone5RegsAccess, which stands in for cs_regs_access, because Capstone 6
// adds X30 to what RET reads inside cs_regs_access itself.
//
// With these rules both versions agree on the access of every operand and on
// every register access to X0-X30, SP and NZCV in all of libc.so, libm.so and
// test_fuzz. On 2M random words 4% of the instructions both decode still
// differ in a tracked-register access, all of them in encodings absent from
// those binaries: SVE and SME, MTE, MOPS, BC.cond, LDRAA/LDRAB, RCPC2 and
// LOR loads and stores, FP16 conditional compares and selects, PACGA, RMIF,
// ST64BV. Capstone 6's answer is kept for these; it is the more complete one
// except for the LDRAA/LDRAB destination, which Capstone 5 did not report as
// written.
inline void emulateCapstone5Access(cs_insn& Insn)
{
    cs_detail& Detail = *Insn.detail;
    cs_aarch64& A = Detail.aarch64;

    auto addTo = [](uint16_t* Regs, uint8_t& Count, uint8_t Max, uint16_t Reg) {
        for(uint8_t I = 0; I < Count; ++I)
        {
            if(Regs[I] == Reg)
            {
                return;
            }
        }
        if(Count < Max)
        {
            Regs[Count++] = Reg;
        }
    };
    auto isReg = [&A](unsigned int Index) {
        return Index < A.op_count && A.operands[Index].type == AARCH64_OP_REG;
    };
    auto isW = [](unsigned int Reg) {
        return (Reg >= AARCH64_REG_W0 && Reg <= AARCH64_REG_W30) || Reg == AARCH64_REG_WZR
               || Reg == AARCH64_REG_WSP;
    };
    auto isH = [](unsigned int Reg) { return Reg >= AARCH64_REG_H0 && Reg <= AARCH64_REG_H31; };
    auto noAccess = [&]() {
        for(unsigned int I = 0; I < A.op_count; ++I)
        {
            A.operands[I].access = CS_AC_INVALID;
        }
        Detail.regs_read_count = 0;
        Detail.regs_write_count = 0;
    };
    const bool IsAlias = Insn.is_alias;

    // J, K: memory operands.
    for(unsigned int I = 0; I < A.op_count; ++I)
    {
        cs_aarch64_op& Op = A.operands[I];
        if(Op.type != AARCH64_OP_MEM)
        {
            continue;
        }
        switch(Insn.id)
        {
            case AARCH64_INS_STLR:
            case AARCH64_INS_STLRB:
            case AARCH64_INS_STLRH:
            case AARCH64_INS_LDXR:
            case AARCH64_INS_LDXRB:
            case AARCH64_INS_LDXRH:
            case AARCH64_INS_LDXP:
            case AARCH64_INS_LDAXR:
            case AARCH64_INS_LDAXRB:
            case AARCH64_INS_LDAXRH:
            case AARCH64_INS_LDAXP:
            case AARCH64_INS_STXR:
            case AARCH64_INS_STXRB:
            case AARCH64_INS_STXRH:
            case AARCH64_INS_STXP:
            case AARCH64_INS_STLXR:
            case AARCH64_INS_STLXRB:
            case AARCH64_INS_STLXRH:
            case AARCH64_INS_STLXP:
                Op.access = CS_AC_READ;
                break;
            case AARCH64_INS_PRFM:
            case AARCH64_INS_PRFUM:
            case AARCH64_INS_STR:
            case AARCH64_INS_STRB:
            case AARCH64_INS_STRH:
            case AARCH64_INS_STUR:
            case AARCH64_INS_STURB:
            case AARCH64_INS_STURH:
            case AARCH64_INS_STP:
            case AARCH64_INS_STNP:
            case AARCH64_INS_STTR:
            case AARCH64_INS_STTRB:
            case AARCH64_INS_STTRH:
                Op.access = CS_AC_READ_WRITE;
                break;
            case AARCH64_INS_LDR:
            {
                // Capstone 5.0.1's LDR access depends on the form. With base
                // writeback: read and written, except for X and S destinations
                // and for a W destination with pre-index, which are only read.
                // With a W index register and a D destination: read and written.
                const unsigned int Dst = isReg(0) ? A.operands[0].reg : AARCH64_REG_INVALID;
                const bool X = (Dst >= AARCH64_REG_X0 && Dst <= AARCH64_REG_X28)
                               || Dst == AARCH64_REG_FP || Dst == AARCH64_REG_LR
                               || Dst == AARCH64_REG_XZR;
                const bool S = Dst >= AARCH64_REG_S0 && Dst <= AARCH64_REG_S31;
                const bool D = Dst >= AARCH64_REG_D0 && Dst <= AARCH64_REG_D31;
                if(Detail.writeback)
                {
                    const bool PreIndex = std::strstr(Insn.op_str, "]!") != nullptr;
                    if(!X && !S && !(isW(Dst) && PreIndex))
                    {
                        Op.access = CS_AC_READ_WRITE;
                    }
                }
                else if(D && isW(Op.mem.index))
                {
                    Op.access = CS_AC_READ_WRITE;
                }
                break;
            }
            case AARCH64_INS_LDRB:
            case AARCH64_INS_LDRH:
            case AARCH64_INS_LDRSB:
            case AARCH64_INS_LDRSH:
            case AARCH64_INS_LDRSW:
            case AARCH64_INS_LDP:
            case AARCH64_INS_LDPSW:
                if(Detail.writeback)
                {
                    Op.access = CS_AC_READ_WRITE;
                }
                break;
            default:
                break;
        }
    }

    // A: CMP/CMN/TST.
    if(IsAlias
       && (Insn.alias_id == AARCH64_INS_ALIAS_CMP || Insn.alias_id == AARCH64_INS_ALIAS_CMN
           || Insn.alias_id == AARCH64_INS_ALIAS_TST)
       && isReg(0))
    {
        A.operands[0].access = CS_AC_WRITE;
    }

    auto clearKind = [&A](aarch64_op_type Type) {
        for(unsigned int I = 0; I < A.op_count; ++I)
        {
            if(A.operands[I].type == Type)
            {
                A.operands[I].access = CS_AC_INVALID;
            }
        }
    };

    switch(Insn.id)
    {
        case AARCH64_INS_MOVZ: // L
        case AARCH64_INS_MOVN:
        case AARCH64_INS_ORR:
            if(IsAlias && Insn.alias_id == AARCH64_INS_ALIAS_MOV)
            {
                clearKind(AARCH64_OP_IMM);
            }
            break;
        case AARCH64_INS_UDF:
        case AARCH64_INS_CMEQ:
        case AARCH64_INS_CMGE:
        case AARCH64_INS_CMGT:
        case AARCH64_INS_CMLE:
        case AARCH64_INS_CMLT:
            clearKind(AARCH64_OP_IMM);
            break;
        case AARCH64_INS_MRS: // M
            if(A.op_count == 2 && A.operands[1].type != AARCH64_OP_REG)
            {
                A.operands[1].access = CS_AC_READ;
            }
            break;
        case AARCH64_INS_MSR:
            if(A.op_count == 2 && A.operands[0].type != AARCH64_OP_REG)
            {
                A.operands[0].access = CS_AC_WRITE;
            }
            break;
        case AARCH64_INS_DMB: // N
        case AARCH64_INS_DSB:
            for(unsigned int I = 0; I < A.op_count; ++I)
            {
                A.operands[I].access = CS_AC_READ;
            }
            break;
        case AARCH64_INS_FCMP: // O
        case AARCH64_INS_FCMPE:
            clearKind(AARCH64_OP_FP);
            break;
        case AARCH64_INS_FCCMP:
        case AARCH64_INS_FCCMPE:
            for(unsigned int I = 0; I < A.op_count; ++I)
            {
                if(A.operands[I].type == AARCH64_OP_IMM)
                {
                    A.operands[I].access = CS_AC_WRITE;
                }
            }
            break;
        case AARCH64_INS_FMOV:
            if(A.op_count == 2 && A.operands[1].type == AARCH64_OP_FP && isReg(0))
            {
                A.operands[0].access = CS_AC_READ_WRITE;
            }
            break;
        case AARCH64_INS_MVNI:
        case AARCH64_INS_SSHR:
        case AARCH64_INS_USHR:
        case AARCH64_INS_URSHR:
            if(isReg(0))
            {
                A.operands[0].access = CS_AC_READ_WRITE;
            }
            break;
        case AARCH64_INS_LD1: // Q
        case AARCH64_INS_LD2:
        case AARCH64_INS_LD3:
        case AARCH64_INS_LD4:
        case AARCH64_INS_LD1R:
        case AARCH64_INS_LD2R:
        case AARCH64_INS_LD3R:
        case AARCH64_INS_LD4R:
        case AARCH64_INS_ST1:
        case AARCH64_INS_ST2:
        case AARCH64_INS_ST3:
        case AARCH64_INS_ST4:
        {
            // Capstone 5.0.1's list, measured per form (number of registers,
            // single lane or whole registers, no post-increment, immediate or
            // register post-increment): the rest of the operands have no
            // access.
            unsigned int N = 0;
            while(N < A.op_count && A.operands[N].type == AARCH64_OP_REG)
            {
                ++N;
            }
            if(N == 0 || N >= A.op_count || A.operands[N].type != AARCH64_OP_MEM)
            {
                break;
            }
            const bool Lane = A.operands[0].vector_index != -1;
            const bool PostImm = N + 1 < A.op_count && A.operands[N + 1].type == AARCH64_OP_IMM;
            const bool PostReg = N + 1 < A.op_count && A.operands[N + 1].type == AARCH64_OP_REG;
            const bool Store = Insn.id == AARCH64_INS_ST1 || Insn.id == AARCH64_INS_ST2
                               || Insn.id == AARCH64_INS_ST3 || Insn.id == AARCH64_INS_ST4;
            const cs_ac_type R = CS_AC_READ, RW = CS_AC_READ_WRITE;
            cs_ac_type List[4] = {CS_AC_INVALID, CS_AC_INVALID, CS_AC_INVALID, CS_AC_INVALID};
            unsigned int Len = 0;
            auto push = [&List, &Len](cs_ac_type Access) { List[Len++] = Access; };
            if(!Store && !Lane)
            {
                push(RW);
                push(RW);
                if(PostReg || (PostImm && N >= 2))
                {
                    push(R);
                }
            }
            else if(!Store)
            {
                push(RW);
                push(N >= 3 ? R : RW);
                if(N >= 3)
                {
                    push(RW);
                }
                if(PostReg || (PostImm && N >= 2))
                {
                    push(R);
                }
            }
            else if(!Lane)
            {
                push(R);
                push(RW);
                if(PostReg || (PostImm && N >= 2))
                {
                    push(R);
                }
            }
            else
            {
                push(R);
                push(R);
                if(N == 1)
                {
                    if(PostReg)
                    {
                        push(RW);
                    }
                }
                else
                {
                    push(RW);
                    if(PostReg || (PostImm && N >= 3))
                    {
                        push(R);
                    }
                }
            }
            for(unsigned int I = 0; I < A.op_count; ++I)
            {
                A.operands[I].access = I < Len ? List[I] : CS_AC_INVALID;
            }
            break;
        }
        case AARCH64_INS_CBZ: // B
        case AARCH64_INS_CBNZ:
            addTo(Detail.regs_read, Detail.regs_read_count, MAX_IMPL_R_REGS, AARCH64_REG_NZCV);
            break;
        case AARCH64_INS_SVC: // D
            addTo(Detail.regs_write, Detail.regs_write_count, MAX_IMPL_W_REGS, AARCH64_REG_LR);
            break;
        case AARCH64_INS_SBFM: // E
        case AARCH64_INS_UBFM:
            if(isReg(0))
            {
                A.operands[0].access = CS_AC_READ_WRITE;
            }
            break;
        case AARCH64_INS_SYS: // F
            if(IsAlias)
            {
                for(unsigned int I = 0; I < A.op_count; ++I)
                {
                    if(isReg(I))
                    {
                        A.operands[I].access = CS_AC_INVALID;
                    }
                }
            }
            break;
        case AARCH64_INS_SYSL:
            if(isReg(0))
            {
                A.operands[0].access = CS_AC_READ_WRITE;
            }
            break;
        case AARCH64_INS_ADDS: // G
            if(isReg(0) && isW(A.operands[0].reg) && A.op_count >= 2
               && A.operands[A.op_count - 1].type == AARCH64_OP_IMM)
            {
                A.operands[0].access = CS_AC_READ;
            }
            break;
        case AARCH64_INS_SCVTF: // I
        case AARCH64_INS_UCVTF:
        case AARCH64_INS_FCVTZS:
        case AARCH64_INS_FCVTZU:
            if((isReg(0) && isH(A.operands[0].reg)) || (isReg(1) && isH(A.operands[1].reg)))
            {
                noAccess();
            }
            break;
#define ARM64_CAPSTONE5_ATOMIC(Op) \
    case AARCH64_INS_##Op:         \
    case AARCH64_INS_##Op##A:      \
    case AARCH64_INS_##Op##AL:     \
    case AARCH64_INS_##Op##L:      \
    case AARCH64_INS_##Op##B:      \
    case AARCH64_INS_##Op##AB:     \
    case AARCH64_INS_##Op##ALB:    \
    case AARCH64_INS_##Op##LB:     \
    case AARCH64_INS_##Op##H:      \
    case AARCH64_INS_##Op##AH:     \
    case AARCH64_INS_##Op##ALH:    \
    case AARCH64_INS_##Op##LH:
            ARM64_CAPSTONE5_ATOMIC(CAS) // H
            ARM64_CAPSTONE5_ATOMIC(SWP)
            ARM64_CAPSTONE5_ATOMIC(LDADD)
            ARM64_CAPSTONE5_ATOMIC(LDCLR)
            ARM64_CAPSTONE5_ATOMIC(LDEOR)
            ARM64_CAPSTONE5_ATOMIC(LDSET)
            ARM64_CAPSTONE5_ATOMIC(LDSMAX)
            ARM64_CAPSTONE5_ATOMIC(LDSMIN)
            ARM64_CAPSTONE5_ATOMIC(LDUMAX)
            ARM64_CAPSTONE5_ATOMIC(LDUMIN)
#undef ARM64_CAPSTONE5_ATOMIC
        case AARCH64_INS_CASP:
        case AARCH64_INS_CASPA:
        case AARCH64_INS_CASPAL:
        case AARCH64_INS_CASPL:
            noAccess();
            break;
        default:
            break;
    }
}

// cs_regs_access as Capstone 5.0.1 answered it for an instruction that went
// through emulateCapstone5Access: RET, RETAA and RETAB without an explicit X30
// operand do not read X30 (rule C), and FPCR, which Capstone 6 lists as read
// by floating-point arithmetic, is never listed (rule P).
inline cs_err capstone5RegsAccess(csh Handle, const cs_insn& Insn, cs_regs RegsRead,
                                  uint8_t* RegsReadCount, cs_regs RegsWrite,
                                  uint8_t* RegsWriteCount)
{
    cs_err Err = cs_regs_access(Handle, &Insn, RegsRead, RegsReadCount, RegsWrite, RegsWriteCount);
    if(Err != CS_ERR_OK)
    {
        return Err;
    }
    auto remove = [](uint16_t* Regs, uint8_t* Count, uint16_t Reg) {
        uint8_t N = 0;
        for(uint8_t I = 0; I < *Count; ++I)
        {
            if(Regs[I] != Reg)
            {
                Regs[N++] = Regs[I];
            }
        }
        *Count = N;
    };
    remove(RegsRead, RegsReadCount, AARCH64_REG_FPCR);
    remove(RegsWrite, RegsWriteCount, AARCH64_REG_FPCR);
    if(Insn.id == AARCH64_INS_RET || Insn.id == AARCH64_INS_RETAA || Insn.id == AARCH64_INS_RETAB)
    {
        const cs_aarch64& A = Insn.detail->aarch64;
        for(unsigned int I = 0; I < A.op_count; ++I)
        {
            if(A.operands[I].type == AARCH64_OP_REG && A.operands[I].reg == AARCH64_REG_LR)
            {
                return Err;
            }
        }
        remove(RegsRead, RegsReadCount, AARCH64_REG_LR);
    }
    return Err;
}

#endif // SRC_GTIRB_DECODER_ARCH_ARM64CAPSTONE_H_
