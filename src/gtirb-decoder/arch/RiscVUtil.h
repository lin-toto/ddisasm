//===- RiscVUtil.h --------------------------------------------*- C++ -*-===//
//
//  Copyright (C) 2026 GrammaTech, Inc.
//
//  This code is licensed under the GNU Affero General Public License
//  as published by the Free Software Foundation, either version 3 of
//  the License, or (at your option) any later version. See the
//  LICENSE.txt file in the project root for license terms or visit
//  https://www.gnu.org/licenses/agpl.txt.
//
//===----------------------------------------------------------------------===//
#ifndef SRC_GTIRB_DECODER_ARCH_RISCVUTIL_H_
#define SRC_GTIRB_DECODER_ARCH_RISCVUTIL_H_

#include <gtirb/gtirb.hpp>

#include "../../AuxDataSchema.h"

enum class RiscVXLen
{
    Unknown,
    RV32,
    RV64
};

inline RiscVXLen getRiscVXLen(const gtirb::Module& Module)
{
    if(auto* ArchInfo = Module.getAuxData<gtirb::schema::ArchInfo>())
    {
        auto It = ArchInfo->find("ISA");
        if(It != ArchInfo->end())
        {
            if(It->second == "RISCV32")
            {
                return RiscVXLen::RV32;
            }
            if(It->second == "RISCV64")
            {
                return RiscVXLen::RV64;
            }
        }
    }
    return RiscVXLen::Unknown;
}

inline const char* getRiscVISAName(RiscVXLen XLen)
{
    switch(XLen)
    {
        case RiscVXLen::RV32:
            return "RISCV32";
        case RiscVXLen::RV64:
            return "RISCV64";
        case RiscVXLen::Unknown:
        default:
            return "RISCV";
    }
}

#endif // SRC_GTIRB_DECODER_ARCH_RISCVUTIL_H_
