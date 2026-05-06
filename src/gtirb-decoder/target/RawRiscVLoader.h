//===- RawRiscVLoader.h ----------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_TARGET_RAWRISCVLOADER_H_
#define SRC_GTIRB_DECODER_TARGET_RAWRISCVLOADER_H_

#include "../CompositeLoader.h"
#include "../arch/RiscVLoader.h"
#include "../arch/RiscVUtil.h"
#include "../core/DataLoader.h"
#include "../core/ModuleLoader.h"
#include "../core/SectionLoader.h"
#include "../format/RawLoader.h"

CompositeLoader RawRiscV32Loader()
{
    CompositeLoader Loader("souffle_disasm_riscv32");
    Loader.add(ModuleLoader);
    Loader.add(SectionLoader);
    Loader.add<RiscVLoader>(RiscVLoader::XLen::RV32);
    Loader.add<DataLoader>(DataLoader::Pointer::DWORD);
    Loader.add(RawEntryLoader);
    return Loader;
}

CompositeLoader RawRiscV64Loader()
{
    CompositeLoader Loader("souffle_disasm_riscv64");
    Loader.add(ModuleLoader);
    Loader.add(SectionLoader);
    Loader.add<RiscVLoader>(RiscVLoader::XLen::RV64);
    Loader.add<DataLoader>(DataLoader::Pointer::QWORD);
    Loader.add(RawEntryLoader);
    return Loader;
}

#if defined(DDISASM_RISCV_32) || defined(DDISASM_RISCV_64)
CompositeLoader RawRiscVLoader(const gtirb::Module& Module)
{
#if defined(DDISASM_RISCV_32) && defined(DDISASM_RISCV_64)
    if(getRiscVXLen(Module) == RiscVXLen::RV32)
    {
        return RawRiscV32Loader();
    }
    return RawRiscV64Loader();
#elif defined(DDISASM_RISCV_32)
    return RawRiscV32Loader();
#else
    return RawRiscV64Loader();
#endif
}
#endif

#endif // SRC_GTIRB_DECODER_TARGET_RAWRISCVLOADER_H_
