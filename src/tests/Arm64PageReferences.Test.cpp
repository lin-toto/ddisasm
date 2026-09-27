// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include "../AuxDataSchema.h"
#include "../passes/Arm64PageReferences.h"

namespace
{
struct PageFixture
{
    gtirb::Context Context;
    gtirb::Module* Module = gtirb::IR::Create(Context)->addModule(Context, "pages");
    gtirb::ByteInterval* Text;
    gtirb::Symbol* Value;

    PageFixture(std::initializer_list<uint32_t> Words)
    {
        Module->setISA(gtirb::ISA::ARM64);
        Module->setByteOrder(gtirb::ByteOrder::Little);
        Text = Module->addSection(Context, ".text")
                   ->addByteInterval(Context, gtirb::Addr(0x400000), Words.size() * 4);
        Text->setInitializedSize(Words.size() * 4);
        unsigned Offset = 0;
        for(uint32_t Word : Words)
            for(unsigned Byte = 0; Byte != 4; ++Byte)
                Text->rawBytes<uint8_t>()[Offset++] = (Word >> (Byte * 8)) & 255;
        Value = Module->addSymbol(Context, gtirb::Addr(0x480040), "value");
        Module->addAuxData<gtirb::schema::SymbolicExpressionSizes>(
            std::map<gtirb::Offset, uint64_t>{});
    }

    gtirb::CodeBlock* block(unsigned Offset, unsigned Size)
    {
        return Text->addBlock<gtirb::CodeBlock>(Context, Offset, Size);
    }

    void edge(gtirb::CodeBlock* From, gtirb::CodeBlock* To,
              gtirb::EdgeType Type = gtirb::EdgeType::Branch)
    {
        auto& CFG = Module->getIR()->getCFG();
        CFG[*addEdge(From, To, CFG)] = std::make_tuple(
            gtirb::ConditionalEdge::OnFalse, gtirb::DirectEdge::IsDirect, Type);
    }

    void high(unsigned Offset = 0, gtirb::SymAttributeSet Attributes = {})
    {
        Text->addSymbolicExpression<gtirb::SymAddrConst>(Offset, 0, Value, Attributes);
    }

    const gtirb::SymAddrConst* low(unsigned Offset)
    {
        const auto* Expr = Text->getSymbolicExpression(Offset);
        return Expr ? std::get_if<gtirb::SymAddrConst>(Expr) : nullptr;
    }
};
} // namespace

TEST(Arm64PageReferences, FinalEdgesAndPreservedLoop)
{
    // ADRP x22,0x480000; NOP; ADD x0,x22,#64
    PageFixture F{0x90000416, 0xd503201f, 0x910102c0};
    auto* High = F.block(0, 4);
    auto* Loop = F.block(4, 4);
    auto* Low = F.block(8, 4);
    F.edge(High, Loop);
    F.edge(Loop, Loop);
    F.edge(Loop, Low);
    F.high();
    completeArm64PageReferences(*F.Module);
    ASSERT_NE(F.low(8), nullptr);
    EXPECT_EQ(F.low(8)->Sym, F.Value);
    EXPECT_EQ(F.low(8)->Attributes, gtirb::SymAttributeSet{gtirb::SymAttribute::LO12});
    EXPECT_EQ(F.Module->getAuxData<gtirb::schema::SymbolicExpressionSizes>()->at(
                  gtirb::Offset(F.Text->getUUID(), 8)), 4);
}

TEST(Arm64PageReferences, RejectsUnknownEntryAndDivergentOrigin)
{
    for(bool HasOtherDefinition : {false, true})
    {
        PageFixture F{0x90000416, HasOtherDefinition ? 0x90000416U : 0xd503201fU,
                      0x910102c0};
        auto* High = F.block(0, 4);
        auto* Other = F.block(4, 4);
        auto* Low = F.block(8, 4);
        F.edge(High, Low);
        F.edge(Other, Low);
        F.high();
        if(HasOtherDefinition)
        {
            auto* Alias = F.Module->addSymbol(F.Context, gtirb::Addr(0x480040), "other");
            F.Text->addSymbolicExpression<gtirb::SymAddrConst>(4, 0, Alias, gtirb::SymAttributeSet{});
        }
        completeArm64PageReferences(*F.Module);
        EXPECT_EQ(F.low(8), nullptr);
    }
}

TEST(Arm64PageReferences, CallsAndPartialRegisterWrites)
{
    for(unsigned Register : {8, 22})
    {
        // A call kills x8 but preserves x22. This is ABI knowledge, not the
        // decoder's explicit BL write list (which contains only the link).
        PageFixture F{0x90000400 | Register, 0x94000000,
                      0x91010000 | Register << 5};
        auto* High = F.block(0, 8);
        auto* Low = F.block(8, 4);
        F.edge(High, Low, gtirb::EdgeType::Fallthrough);
        F.high();
        completeArm64PageReferences(*F.Module);
        EXPECT_EQ(F.low(8) != nullptr, Register == 22);
    }
    // MOV w22,#0 destroys the saved full-width page too.
    PageFixture F{0x90000416, 0x52800016, 0x910102c0};
    F.block(0, 12);
    F.high();
    completeArm64PageReferences(*F.Module);
    EXPECT_EQ(F.low(8), nullptr);
}

TEST(Arm64PageReferences, NoGuessesForGotCompletedAddressOrUnrootedCycle)
{
    PageFixture Got{0x90000416, 0x910102c0};
    Got.block(0, 8);
    Got.high(0, {gtirb::SymAttribute::GOT});
    completeArm64PageReferences(*Got.Module);
    EXPECT_EQ(Got.low(4), nullptr);

    // ADD completes the address; a following LDR's offset is not a page use.
    PageFixture Completed{0x90000416, 0x910102d6, 0xb94042c0};
    Completed.block(0, 12);
    Completed.high();
    completeArm64PageReferences(*Completed.Module);
    EXPECT_NE(Completed.low(4), nullptr);
    EXPECT_EQ(Completed.low(8), nullptr);

    PageFixture Cycle{0xd503201f, 0x910102c0};
    auto* Loop = Cycle.block(0, 4);
    auto* Low = Cycle.block(4, 4);
    Cycle.edge(Loop, Loop);
    Cycle.edge(Loop, Low);
    completeArm64PageReferences(*Cycle.Module);
    EXPECT_EQ(Cycle.low(4), nullptr);
}

namespace
{
uint32_t pageAdr(unsigned Register, uint64_t Address = 0x400ff8)
{
    uint32_t Delta = 0x480000 - Address;
    return 0x10000000 | (Delta & 3) << 29 | ((Delta >> 2) & 0x7ffff) << 5 | Register;
}

void pageDifference(PageFixture& F, unsigned Offset = 4)
{
    F.Module->setFileFormat(gtirb::FileFormat::ELF);
    F.Text->setAddress(gtirb::Addr(0x400ff8));
    auto* Page = F.Module->addSymbol(F.Context, gtirb::Addr(0x480000), "page");
    F.Text->addSymbolicExpression<gtirb::SymAddrAddr>(
        Offset, 1, 0, F.Value, Page, gtirb::SymAttributeSet{});
}
} // namespace

TEST(Arm64PageReferences, RestoresPageOnlyAdrAndGot)
{
    for(bool Got : {false, true})
    {
        // ADR x1,page; LDR w1 (or x1 for GOT),[x1,#64] kills the exact page.
        PageFixture F{pageAdr(1), Got ? 0xf9402021U : 0xb9404021U};
        F.block(0, 8);
        pageDifference(F);
        if(Got)
        {
            auto* Data = F.Module->addSection(F.Context, ".got")
                             ->addByteInterval(F.Context, gtirb::Addr(0x480040), 8)
                             ->addBlock<gtirb::DataBlock>(F.Context, 0, 8);
            F.Value->setReferent(Data);
            auto* Import = F.Module->addSymbol(F.Context, "import");
            F.Module->addAuxData<gtirb::schema::SymbolForwarding>(
                std::map<gtirb::UUID, gtirb::UUID>{{F.Value->getUUID(), Import->getUUID()}});
        }
        completeArm64PageReferences(*F.Module);
        ASSERT_NE(F.low(0), nullptr);
        ASSERT_NE(F.low(4), nullptr);
        EXPECT_EQ(F.low(0)->Sym, F.Value);
        EXPECT_EQ(F.low(0)->Attributes.count(gtirb::SymAttribute::GOT), Got ? 1U : 0U);
        EXPECT_EQ(F.low(4)->Attributes.count(gtirb::SymAttribute::GOT), Got ? 1U : 0U);
        EXPECT_EQ(F.low(4)->Attributes.count(gtirb::SymAttribute::LO12), 1U);
        EXPECT_EQ(F.Text->rawBytes<uint8_t>()[3] & 0x9f, 0x90); // ADRP
    }
}

TEST(Arm64PageReferences, GotLowRequiresPointerLoad)
{
    // LDR w1, STR x0, or ADD x1 at a forwarded slot must not become
    // LD64_GOT_LO12_NC merely because the original effective address matches.
    for(uint32_t Low : {0xb9404021U, 0xf9002020U, 0x91010021U})
    {
        PageFixture F{pageAdr(1), Low, 0x52800001};
        F.block(0, 12);
        pageDifference(F);
        auto* Data = F.Module->addSection(F.Context, ".got")
                         ->addByteInterval(F.Context, gtirb::Addr(0x480040), 8)
                         ->addBlock<gtirb::DataBlock>(F.Context, 0, 8);
        F.Value->setReferent(Data);
        auto* Import = F.Module->addSymbol(F.Context, "import");
        F.Module->addAuxData<gtirb::schema::SymbolForwarding>(
            std::map<gtirb::UUID, gtirb::UUID>{{F.Value->getUUID(), Import->getUUID()}});
        completeArm64PageReferences(*F.Module);
        EXPECT_EQ(F.low(0), nullptr);
        EXPECT_TRUE(std::holds_alternative<gtirb::SymAddrAddr>(*F.Text->getSymbolicExpression(4)));
    }
}

TEST(Arm64PageReferences, ExactPageMustNotEscape)
{
    for(bool StoredPage : {false, true})
    {
        // A live-out exact base, or STR x1,[x1,#64] followed by killing x1,
        // must not change the observed page even though its address tail is
        // target-page. Merely finding one memory operand isn't enough.
        PageFixture F{pageAdr(1), StoredPage ? 0xf9002021U : 0xb9404020U,
                      StoredPage ? 0x52800001U : 0xd65f03c0U};
        F.block(0, 12);
        pageDifference(F);
        completeArm64PageReferences(*F.Module);
        EXPECT_EQ(F.low(0), nullptr);
        EXPECT_TRUE(std::holds_alternative<gtirb::SymAddrAddr>(*F.Text->getSymbolicExpression(4)));
        EXPECT_EQ(F.Text->rawBytes<uint8_t>()[3] & 0x9f, 0x10); // ADR
    }
}
