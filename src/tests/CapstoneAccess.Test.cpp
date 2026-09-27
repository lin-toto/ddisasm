#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "../gtirb-decoder/arch/Arm64Loader.h"
#include "../gtirb-decoder/arch/X64Loader.h"

namespace
{
template <typename Loader> class ExposedLoader : public Loader
{
public:
    using Loader::decode;
};

template <typename Loader> BinaryFacts decode(std::initializer_list<uint8_t> Bytes)
{
    ExposedLoader<Loader> L;
    BinaryFacts Facts;
    L.decode(Facts, Bytes.begin(), Bytes.size(), 0x10000);
    return Facts;
}

std::set<std::string> registers(const BinaryFacts& Facts, const std::string& Mode)
{
    std::set<std::string> Result;
    for(const auto& Access : Facts.Instructions.registerAccesses())
    {
        if(Access.Mode == Mode)
        {
            Result.insert(Access.Register);
        }
    }
    return Result;
}
} // namespace

TEST(CapstoneAccess, AArch64NativeReadsAndWrites)
{
    const auto Cmp = decode<Arm64Loader>({0x1f, 0x00, 0x01, 0xeb}); // cmp x0,x1
    EXPECT_EQ(registers(Cmp, "R"), (std::set<std::string>{"X0", "X1"}));
    EXPECT_EQ(registers(Cmp, "W"), (std::set<std::string>{"NZCV"}));
    const auto Cbz = decode<Arm64Loader>({0x42, 0x00, 0x00, 0xb4}); // cbz x2,+8
    EXPECT_EQ(registers(Cbz, "R"), (std::set<std::string>{"X2"}));
    EXPECT_TRUE(registers(Cbz, "W").empty());
    const auto Ret = decode<Arm64Loader>({0xc0, 0x03, 0x5f, 0xd6});
    EXPECT_EQ(registers(Ret, "R"), (std::set<std::string>{"LR"}));
    const auto Svc = decode<Arm64Loader>({0x01, 0x00, 0x00, 0xd4});
    EXPECT_TRUE(registers(Svc, "W").empty());

    const auto Store = decode<Arm64Loader>({0x20, 0x00, 0x00, 0xf9}); // str x0,[x1]
    bool ReadMemory = false, WroteMemory = false;
    for(const auto& Access : Store.Instructions.opAccess())
    {
        if(Access.Index == 1) // Memory operand, after destination rotation.
        {
            ReadMemory |= Access.Mode == "R";
            WroteMemory |= Access.Mode == "W";
        }
    }
    EXPECT_FALSE(ReadMemory);
    EXPECT_TRUE(WroteMemory);
}

TEST(CapstoneAccess, AArch64CompareExchangeDoesNotWriteItsAddress)
{
    // Correct real Alpha11 errors, not the previous decoder's access sets.
    const auto Cas = decode<Arm64Loader>({0x41, 0x7c, 0xa0, 0xc8}); // cas x0,x1,[x2]
    EXPECT_EQ(registers(Cas, "R"), (std::set<std::string>{"X0", "X1", "X2"}));
    EXPECT_EQ(registers(Cas, "W"), (std::set<std::string>{"X0"}));
    const auto Casal = decode<Arm64Loader>({0xc5, 0xfc, 0xe4, 0x88}); // casal w4,w5,[x6]
    EXPECT_EQ(registers(Casal, "R"), (std::set<std::string>{"W4", "W5", "X6"}));
    EXPECT_EQ(registers(Casal, "W"), (std::set<std::string>{"W4"}));
    const auto Casp = decode<Arm64Loader>({0x82, 0x7c, 0x20, 0x48}); // casp x0,x1,x2,x3,[x4]
    EXPECT_EQ(registers(Casp, "R"), (std::set<std::string>{"X0", "X1", "X2", "X3", "X4"}));
    EXPECT_EQ(registers(Casp, "W"), (std::set<std::string>{"X0", "X1"}));
}

TEST(CapstoneAccess, X64AcceptsValidMovsxdButRejectsRexVex)
{
    // MOVSXD without REX.W is valid, though discouraged. The old decoder
    // rejected it; reproducing that rejection loses real code candidates.
    const auto Mov = decode<X64Loader>({0x63, 0xc0});
    ASSERT_EQ(Mov.Instructions.instructions().size(), 1);
    EXPECT_EQ(Mov.Instructions.instructions()[0].Name, "MOVSXD");
    EXPECT_TRUE(Mov.Instructions.invalid().empty());
    // REX before VEX is architecturally invalid even if Alpha11 decodes it.
    const auto Vex = decode<X64Loader>({0x48, 0xc5, 0xf8, 0x77});
    EXPECT_TRUE(Vex.Instructions.instructions().empty());
    EXPECT_EQ(Vex.Instructions.invalid().size(), 1);
}

TEST(CapstoneAccess, X64CompareExchangePairs)
{
    for(const bool Wide : {false, true})
    {
        const auto Facts = Wide ? decode<X64Loader>({0x48, 0x0f, 0xc7, 0x0f})
                                : decode<X64Loader>({0x0f, 0xc7, 0x0f});
        EXPECT_EQ(registers(Facts, "R"),
                  Wide ? (std::set<std::string>{"RAX", "RBX", "RCX", "RDX", "RDI"})
                       : (std::set<std::string>{"EAX", "EBX", "ECX", "EDX", "RDI"}));
        EXPECT_EQ(registers(Facts, "W"),
                  Wide ? (std::set<std::string>{"RAX", "RDX", "RFLAGS"})
                       : (std::set<std::string>{"EAX", "EDX", "RFLAGS"}));
    }
}
