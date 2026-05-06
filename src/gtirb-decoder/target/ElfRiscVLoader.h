//===- ElfRiscVLoader.h ----------------------------------------*- C++ -*-===//
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
#ifndef SRC_GTIRB_DECODER_TARGET_ELFRISCVLOADER_H_
#define SRC_GTIRB_DECODER_TARGET_ELFRISCVLOADER_H_

#include "../CompositeLoader.h"
#include "../arch/RiscVLoader.h"
#include "../arch/RiscVUtil.h"
#include "../core/DataLoader.h"
#include "../core/ModuleLoader.h"
#include "../core/SectionLoader.h"
#include "../format/ElfLoader.h"

CompositeLoader ElfRiscV32Loader()
{
    CompositeLoader Loader("souffle_disasm_riscv32");
    Loader.add(ModuleLoader);
    Loader.add(SectionLoader);
    Loader.add<RiscVLoader>(RiscVLoader::XLen::RV32);
    Loader.add<DataLoader>(DataLoader::Pointer::DWORD);
    Loader.add(ElfDynamicEntryLoader);
    Loader.add(ElfSymbolLoader);
    Loader.add(ElfExceptionLoader);
    return Loader;
}

CompositeLoader ElfRiscV64Loader()
{
    CompositeLoader Loader("souffle_disasm_riscv64");
    Loader.add(ModuleLoader);
    Loader.add(SectionLoader);
    Loader.add<RiscVLoader>(RiscVLoader::XLen::RV64);
    Loader.add<DataLoader>(DataLoader::Pointer::QWORD);
    Loader.add(ElfDynamicEntryLoader);
    Loader.add(ElfSymbolLoader);
    Loader.add(ElfExceptionLoader);
    return Loader;
}

#if defined(DDISASM_RISCV_32) || defined(DDISASM_RISCV_64)
CompositeLoader ElfRiscVLoader(const gtirb::Module& Module)
{
#if defined(DDISASM_RISCV_32) && defined(DDISASM_RISCV_64)
    if(getRiscVXLen(Module) == RiscVXLen::RV32)
    {
        return ElfRiscV32Loader();
    }
    return ElfRiscV64Loader();
#elif defined(DDISASM_RISCV_32)
    return ElfRiscV32Loader();
#else
    return ElfRiscV64Loader();
#endif
}
#endif

#endif // SRC_GTIRB_DECODER_TARGET_ELFRISCVLOADER_H_
