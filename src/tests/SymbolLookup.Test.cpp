// Copyright (C) 2026. SPDX-License-Identifier: AGPL-3.0-or-later

#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

#include "../AuxDataSchema.h"

// Test the lookup used by GOT forwarding without relying on a linker-specific
// executable layout or giving this implementation helper a new public API.
gtirb::Symbol *findFirstSymbol(gtirb::Module &, std::string, bool);

namespace
{
class SymbolLookupTest : public ::testing::Test
{
protected:
    gtirb::Context Context;
    gtirb::Module *Module = gtirb::IR::Create(Context)->addModule(Context, "lookup");

    void SetUp() override
    {
        Module->addAuxData<gtirb::schema::ElfSymbolInfo>(
            std::map<gtirb::UUID, auxdata::ElfSymbolInfo>{});
    }

    gtirb::Symbol *add(const std::string &Name, const std::string &Binding, uint64_t Address)
    {
        auto *Symbol = Module->addSymbol(Context, gtirb::Addr(Address), Name);
        Module->getAuxData<gtirb::schema::ElfSymbolInfo>()->emplace(
            Symbol->getUUID(), auxdata::ElfSymbolInfo{0, "OBJECT", Binding, "DEFAULT", 1});
        return Symbol;
    }

    std::pair<gtirb::Symbol *, std::string> lookup(const std::string &Name)
    {
        std::ostringstream Diagnostics;
        auto *Previous = std::cerr.rdbuf(Diagnostics.rdbuf());
        auto *Symbol = findFirstSymbol(*Module, Name, true);
        std::cerr.rdbuf(Previous);
        return {Symbol, Diagnostics.str()};
    }
};
} // namespace

TEST_F(SymbolLookupTest, UniqueLocalIsNotAnUnresolvedGlobal)
{
    // Cover a generic local name too: this is not a special case for _DYNAMIC.
    for(const std::string Name : {"_DYNAMIC", "private_table"})
    {
        auto *Expected = add(Name, "LOCAL", 0x2000);
        const auto [Symbol, Diagnostic] = lookup(Name);
        EXPECT_EQ(Symbol, Expected);
        EXPECT_TRUE(Diagnostic.empty()) << Diagnostic;
    }
}

TEST_F(SymbolLookupTest, GlobalAndWeakStillTakePrecedence)
{
    for(const std::string Binding : {"GLOBAL", "WEAK"})
    {
        const std::string Name = "same_name_" + Binding;
        add(Name, "LOCAL", 0x2000);
        auto *Expected = add(Name, Binding, 0x3000);
        const auto [Symbol, Diagnostic] = lookup(Name);
        EXPECT_EQ(Symbol, Expected);
        EXPECT_TRUE(Diagnostic.empty()) << Diagnostic;
    }
}

TEST_F(SymbolLookupTest, AmbiguousLocalsStillWarn)
{
    add("ambiguous", "LOCAL", 0x2000);
    add("ambiguous", "LOCAL", 0x3000);
    const auto [Symbol, Diagnostic] = lookup("ambiguous");
    EXPECT_NE(Symbol, nullptr);
    EXPECT_NE(Diagnostic.find("WARNING: Could not find GLOBAL/WEAK"), std::string::npos);
}

TEST_F(SymbolLookupTest, MissingBindingMetadataStillWarns)
{
    auto *Expected = Module->addSymbol(Context, gtirb::Addr(0x2000), "unknown");
    const auto [Symbol, Diagnostic] = lookup("unknown");
    EXPECT_EQ(Symbol, Expected);
    EXPECT_NE(Diagnostic.find("WARNING: Could not find GLOBAL/WEAK"), std::string::npos);
}
