//===- RiscVLoader.h -------------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_ARCH_RISCVLOADER_H_
#define SRC_GTIRB_DECODER_ARCH_RISCVLOADER_H_

#include <capstone/capstone.h>

#include <gtirb_pprinter/CapstoneCompat.hpp>
#include <optional>
#include <string>

#include "../Relations.h"
#include "../core/InstructionLoader.h"

class RiscVLoader : public InstructionLoader
{
public:
    enum class XLen
    {
        RV32,
        RV64
    };

    explicit RiscVLoader(XLen XLen0)
        : InstructionLoader{2},
          PointerSize{static_cast<uint8_t>(XLen0 == XLen::RV32 ? 4 : 8)}
    {
        // Setup Capstone engine: RV32GC or RV64GC with real (non-alias)
        // syntax and details, the configuration capstone_compat::adaptRiscv
        // expects (gtirb-pprinter uses the same one).
        [[maybe_unused]] cs_err Err =
            capstone_compat::openRiscv(XLen0 == XLen::RV64, false, CsHandle.get());
        assert(Err == CS_ERR_OK && "Failed to initialize RISC-V disassembler.");
    }

protected:
    void load(const gtirb::Module& Module, const gtirb::ByteInterval& ByteInterval,
              BinaryFacts& Facts) override;
    void decode(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size, uint64_t Addr) override;
    uint8_t operandCount(const cs_insn& CsInstruction) override;
    uint8_t operandAccess(const cs_insn& CsInstruction, uint64_t Index) override;

private:
    std::optional<relations::Operand> build(const cs_riscv_op& CsOp, const std::string& Name);
    std::optional<relations::Instruction> build(BinaryFacts& Facts, const cs_insn& CsInstruction);
    uint64_t decodeInstruction(BinaryFacts& Facts, const uint8_t* Bytes, uint64_t Size,
                               uint64_t Addr);
    std::string registerName(unsigned int Reg) const;
    uint8_t memoryAccessSize(const std::string& Name) const;

    uint8_t PointerSize;
};

#endif // SRC_GTIRB_DECODER_ARCH_RISCVLOADER_H_
