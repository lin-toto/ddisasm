// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <map>
#include <set>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/core/DataLoader.h"

namespace
{
class ExposedDataLoader : public DataLoader
{
public:
    using DataLoader::DataLoader;
    using DataLoader::load;
};
} // namespace

TEST(DataLoader, DoesNotInferPointersFromElfNotesOrNonAllocatedBytes)
{
    for(auto Width : {DataLoader::Pointer::DWORD, DataLoader::Pointer::QWORD})
    {
        gtirb::Context Context;
        auto* Module = gtirb::IR::Create(Context)->addModule(Context, "metadata");
        Module->setFileFormat(gtirb::FileFormat::ELF);
        std::map<gtirb::UUID, std::tuple<uint64_t, uint64_t>> Properties;
        auto Add = [&](const char* Name, uint64_t Address, uint64_t Type, bool Loaded) {
            auto* Section = Module->addSection(Context, Name);
            Section->addFlag(gtirb::SectionFlag::Initialized);
            if(Loaded)
                Section->addFlag(gtirb::SectionFlag::Loaded);
            Properties[Section->getUUID()] = {Type, Loaded ? 2 : 0};
            auto* Bytes = Section->addByteInterval(Context, gtirb::Addr(Address), 8);
            Bytes->setInitializedSize(8);
            for(unsigned I = 0; I < 8; ++I)
                Bytes->rawBytes<uint8_t>()[I] = (uint64_t(0x30000) >> (8 * I)) & 255;
        };
        Add(".note.gnu.build-id", 0x10000, 7, true);
        Add("custom_note_name", 0x11000, 7, true);
        Add(".nonallocated", 0x12000, 1, false);
        // Section type, not a name prefix, distinguishes metadata from data.
        Add(".note.ordinary-data", 0x18000, 1, true);
        Add(".data", 0x30000, 1, true);
        Module->addAuxData<gtirb::schema::SectionProperties>(std::move(Properties));
        DataFacts Facts;
        ExposedDataLoader(Width).load(*Module, Facts);
        std::set<uint64_t> Sources;
        for(const auto& Address : Facts.Addresses)
            Sources.insert(uint64_t(Address.Addr));
        EXPECT_EQ(Sources, (std::set<uint64_t>{0x18000, 0x30000}));
    }
}
