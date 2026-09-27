#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "../gtirb-decoder/arch/Arm64Loader.h"
#include "../gtirb-decoder/arch/RiscVLoader.h"
#include "../gtirb-decoder/arch/X64Loader.h"

namespace
{
template <typename Loader> class ExposedLoader : public Loader
{
public:
    using Loader::Loader;
    using Loader::decode;
};

template <typename Loader> BinaryFacts decode(std::initializer_list<uint8_t> Bytes)
{
    ExposedLoader<Loader> L;
    BinaryFacts Facts;
    L.decode(Facts, Bytes.begin(), Bytes.size(), 0x10000);
    return Facts;
}

BinaryFacts decodeRiscv(std::initializer_list<uint8_t> Bytes)
{
    ExposedLoader<RiscVLoader> L(RiscVLoader::XLen::RV64);
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
    EXPECT_EQ(registers(Ret, "R"), (std::set<std::string>{"X30"}));
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

TEST(CapstoneAccess, RiscVNativeControlFlowAndCsrOperands)
{
    const auto Call = decodeRiscv({0xef, 0x00, 0x80, 0x00}); // jal ra,+8
    ASSERT_EQ(Call.Instructions.instructions().size(), 1);
    EXPECT_EQ(Call.Instructions.instructions()[0].Name, "JAL");
    ASSERT_EQ(Call.Operands.imm().size(), 1);
    // Native Capstone 6 branch operands are absolute targets.
    EXPECT_EQ(Call.Operands.imm().begin()->first.Value, 0x10008);
    EXPECT_EQ(registers(Call, "W"), (std::set<std::string>{"RA"}));
    const auto Tail = decodeRiscv({0x67, 0x00, 0x83, 0x00}); // jalr zero,8(t1)
    ASSERT_EQ(Tail.Instructions.instructions().size(), 1);
    EXPECT_EQ(Tail.Instructions.instructions()[0].Name, "JALR");
    EXPECT_EQ(Tail.Instructions.instructions()[0].OpCodes.size(), 3);

    const auto Csr = decodeRiscv({0x73, 0x25, 0x10, 0x00}); // csrrs a0,fflags,zero
    ASSERT_EQ(Csr.Instructions.instructions().size(), 1);
    EXPECT_EQ(Csr.Instructions.instructions()[0].Name, "CSRRS");
    ASSERT_EQ(Csr.Operands.special().size(), 1);
    EXPECT_EQ(Csr.Operands.special().begin()->first.Type, "CSR");
    EXPECT_EQ(Csr.Operands.special().begin()->first.Value, "1");
    EXPECT_EQ(registers(Csr, "W"), (std::set<std::string>{"A0"}));
}

TEST(CapstoneAccess, RiscVCompressedAndAtomicAccesses)
{
    const auto Add = decodeRiscv({0x2e, 0x95}); // c.add a0,a1
    EXPECT_EQ(registers(Add, "R"), (std::set<std::string>{"A0", "A1"}));
    EXPECT_EQ(registers(Add, "W"), (std::set<std::string>{"A0"}));
    const auto Stack = decodeRiscv({0x08, 0x08}); // c.addi4spn a0,sp,16
    EXPECT_EQ(registers(Stack, "R"), (std::set<std::string>{"SP"}));
    EXPECT_EQ(Stack.Instructions.instructions()[0].OpCodes.size(), 3);
    const auto Call = decodeRiscv({0x82, 0x90}); // c.jalr ra
    EXPECT_EQ(registers(Call, "R"), (std::set<std::string>{"RA"}));
    EXPECT_EQ(registers(Call, "W"), (std::set<std::string>{"RA"}));
    const auto Store = decodeRiscv({0x2f, 0x25, 0xb6, 0x18}); // sc.w a0,a1,(a2)
    EXPECT_EQ(registers(Store, "R"), (std::set<std::string>{"A1", "A2"}));
    EXPECT_EQ(registers(Store, "W"), (std::set<std::string>{"A0"}));
    ASSERT_EQ(Store.Operands.indirect().size(), 1);
    EXPECT_EQ(Store.Operands.indirect().begin()->first.Size, 4);
    for(const auto& Access : Store.Instructions.opAccess())
    {
        if(Access.Index == 1)
            EXPECT_EQ(Access.Mode, "W");
    }
    const auto Amo = decodeRiscv({0x2f, 0x25, 0xb6, 0x0e}); // amoswap.w.aqrl
    ASSERT_EQ(Amo.Operands.indirect().size(), 1);
    EXPECT_EQ(Amo.Operands.indirect().begin()->first.Size, 4);
}

TEST(CapstoneAccess, AArch64NativeMemoryAndShiftShapes)
{
    const auto Post = decode<Arm64Loader>({0x20, 0x04, 0x41, 0xf8});
    ASSERT_EQ(Post.Instructions.instructions().size(), 1);
    EXPECT_EQ(Post.Instructions.instructions()[0].OpCodes.size(), 2);
    ASSERT_EQ(Post.Operands.indirect().size(), 1);
    EXPECT_EQ(Post.Operands.indirect().begin()->first.Disp, 16);
    EXPECT_EQ(Post.Instructions.postIndex().size(), 1);
    const auto Literal = decode<Arm64Loader>({0x80, 0x00, 0x00, 0x58});
    ASSERT_EQ(Literal.Operands.indirect().size(), 1);
    EXPECT_EQ(Literal.Operands.indirect().begin()->first.Reg2, "NONE");
    EXPECT_EQ(Literal.Operands.indirect().begin()->first.Disp, 0x10010);
    const auto Shift = decode<Arm64Loader>({0x20, 0xf0, 0x7d, 0xd3});
    ASSERT_EQ(Shift.Instructions.instructions().size(), 1);
    EXPECT_EQ(Shift.Instructions.instructions()[0].OpCodes.size(), 2);
    ASSERT_EQ(Shift.Instructions.shiftedOps().size(), 1);
    EXPECT_EQ(Shift.Instructions.shiftedOps()[0].Shift, 3);
    const auto VariableShift = decode<Arm64Loader>({0x20, 0x20, 0xc2, 0x9a});
    ASSERT_EQ(VariableShift.Instructions.instructions().size(), 1);
    EXPECT_EQ(VariableShift.Instructions.instructions()[0].OpCodes.size(), 2);
    EXPECT_EQ(VariableShift.Instructions.shiftedWithRegOps().size(), 1);
    EXPECT_EQ(registers(VariableShift, "R"), (std::set<std::string>{"X1", "X2"}));
}

TEST(CapstoneAccess, AArch64AtomicSwapReadsAndWritesMemory)
{
    const auto Swap = decode<Arm64Loader>({0xe6, 0x80, 0x25, 0xf8}); // swp x5,x6,[x7]
    EXPECT_EQ(registers(Swap, "R"), (std::set<std::string>{"X5", "X7"}));
    EXPECT_EQ(registers(Swap, "W"), (std::set<std::string>{"X6"}));
    std::set<std::string> MemoryAccess;
    for(const auto& Access : Swap.Instructions.opAccess())
    {
        if(Access.Index == 2) // Native third operand, after first-operand rotation.
            MemoryAccess.insert(Access.Mode);
    }
    EXPECT_EQ(MemoryAccess, (std::set<std::string>{"R", "W"}));
}

TEST(CapstoneAccess, AArch64NativeSystemAndPredicateOperands)
{
    const auto Prefetch = decode<Arm64Loader>({0x00, 0x00, 0x80, 0xf9});
    ASSERT_EQ(Prefetch.Instructions.instructions().size(), 1);
    EXPECT_EQ(Prefetch.Instructions.instructions()[0].OpCodes.size(), 2);
    ASSERT_EQ(Prefetch.Operands.special().size(), 1);
    const auto Bti = decode<Arm64Loader>({0x5f, 0x24, 0x03, 0xd5});
    ASSERT_EQ(Bti.Instructions.instructions().size(), 1);
    EXPECT_EQ(Bti.Instructions.instructions()[0].OpCodes.size(), 1);
    const auto Sve = decode<Arm64Loader>({0x20, 0x80, 0xd8, 0x65});
    ASSERT_EQ(Sve.Instructions.instructions().size(), 1);
    ASSERT_EQ(Sve.Operands.fp_imm().size(), 1);
    EXPECT_EQ(Sve.Operands.fp_imm().begin()->first.Value, 1.0);
    EXPECT_TRUE(Sve.Instructions.writeback().empty()); // tied vector, not base writeback
    EXPECT_EQ(registers(Sve, "R"), (std::set<std::string>{"Z0", "P0"}));
}
