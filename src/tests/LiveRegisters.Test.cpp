//===- LiveRegisters.Test.cpp -----------------------------------*- C++ -*-===//
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

#include <gtest/gtest.h>
#include <souffle/CompiledSouffle.h>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/DatalogIO.h"
#include "../passes/Disassembler.h"

TEST(LiveRegistersTest, OverlappingBlocks)
{
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::LiveRegisterNames>();
    gtirb::AuxDataContainer::registerAuxDataType<gtirb::schema::LiveRegisterSets>();
    auto Program = std::unique_ptr<souffle::SouffleProgram>(
        souffle::ProgramFactory::newInstance("souffle_disasm_x86_64"));
    ASSERT_NE(Program, nullptr);
    gtirb::Context Context;
    auto *IR = gtirb::IR::Create(Context);
    auto *Module = IR->addModule(Context, "overlapping");
    auto *Section = Module->addSection(Context, ".text");
    auto *Interval = Section->addByteInterval(Context, gtirb::Addr(0x1000), 12);
    auto *First = Interval->addBlock<gtirb::CodeBlock>(Context, 0, 8);
    auto *Second = Interval->addBlock<gtirb::CodeBlock>(Context, 4, 8);
    auto *Short = Interval->addBlock<gtirb::CodeBlock>(Context, 0, 4);

    DatalogIO::insertTuple("0\trax", *Program,
                          Program->getRelation("live_register_name"));
    DatalogIO::insertTuple("1\trbx", *Program,
                          Program->getRelation("live_register_name"));
    for(const char *Tuple : {"0x1000\t0x1000", "0x1004\t0x1000",
                            "0x1004\t0x1004", "0x1008\t0x1004"})
    {
        DatalogIO::insertTuple(Tuple, *Program,
                              Program->getRelation("code_in_refined_block"));
    }
    for(const char *Tuple : {"0x1000\t0", "0x1004\t0", "0x1004\t1"})
    {
        DatalogIO::insertTuple(Tuple, *Program, Program->getRelation("live_register"));
    }

    buildLiveRegisters(*Module, *Program);
    const auto *Masks = Module->getAuxData<gtirb::schema::LiveRegisterSets>();
    ASSERT_NE(Masks, nullptr);
    EXPECT_EQ(Masks->at(gtirb::Offset(First->getUUID(), 0)), 1);
    EXPECT_EQ(Masks->at(gtirb::Offset(First->getUUID(), 4)), 3);
    EXPECT_EQ(Masks->at(gtirb::Offset(Second->getUUID(), 0)), 3);
    EXPECT_EQ(Masks->at(gtirb::Offset(Short->getUUID(), 0)), 1);
    // A genuinely dead instruction differs from an unrepresented instruction.
    EXPECT_EQ(Masks->at(gtirb::Offset(Second->getUUID(), 4)), 0);
    EXPECT_EQ(Masks->count(gtirb::Offset(Second->getUUID(), 5)), 0);
    EXPECT_EQ(Masks->count(gtirb::Offset(Short->getUUID(), 4)), 0);
    EXPECT_EQ(Masks->size(), 5);
}
