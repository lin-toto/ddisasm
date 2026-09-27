// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Arm64PageReferences.h"

#include <algorithm>
#include <bitset>
#include <cstdlib>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "../AuxDataSchema.h"
#include "../gtirb-decoder/arch/Arm64Capstone.h"

namespace
{
// Only the full GPR identity is relevant to page values: a W-register write
// also destroys the corresponding X-register value. SP/ZR are not candidates.
int registerNumber(csh Handle, unsigned Register)
{
    const char* Name = cs_reg_name(Handle, Register);
    if(!Name)
        return -1;
    if(std::string(Name) == "fp")
        return 29;
    if(std::string(Name) == "lr")
        return 30;
    if((Name[0] != 'x' && Name[0] != 'w') || Name[1] < '0' || Name[1] > '9')
        return -1;
    char* End;
    long Number = std::strtol(Name + 1, &End, 10);
    return *End == '\0' && Number < 31 ? static_cast<int>(Number) : -1;
}

struct Instruction
{
    uint64_t Address;
    std::bitset<31> Writes;
    bool Call;
    std::bitset<31> Reads;
    std::bitset<31> LowValueReads;
    int LowRegister = -1;
    uint64_t LowOffset = 0;
    bool GotLoad = false;
    int PageRegister = -1;
    uint64_t Page = 0;
    int ExactRegister = -1;
    uint64_t ExactAddress = 0;
};

struct BlockState
{
    std::vector<Instruction> Instructions;
    std::vector<const gtirb::CodeBlock*> Predecessors;
    bool UnknownEntry = false;
    bool Complete = false;
};

struct PageDefinition
{
    gtirb::Symbol* Symbol;
    int64_t Addend;
    uint64_t Page;

    bool operator==(const PageDefinition& Other) const
    {
        return Symbol == Other.Symbol && Addend == Other.Addend && Page == Other.Page;
    }
};

const gtirb::SymbolicExpression* expression(const gtirb::CodeBlock& Block, uint64_t Address)
{
    const auto* Interval = Block.getByteInterval();
    return Interval->getSymbolicExpression(Address - uint64_t(*Interval->getAddress()));
}

std::optional<PageDefinition> definition(const gtirb::CodeBlock& Block,
                                         const Instruction& Insn, int Register)
{
    if(Insn.PageRegister != Register)
        return std::nullopt;
    const auto* Expr = expression(Block, Insn.Address);
    const auto* Constant = Expr ? std::get_if<gtirb::SymAddrConst>(Expr) : nullptr;
    if(!Constant || !Constant->Attributes.empty() || !Constant->Sym->getAddress())
        return std::nullopt;
    uint64_t Target = uint64_t(*Constant->Sym->getAddress()) + Constant->Offset;
    if((Target & ~uint64_t(4095)) != Insn.Page)
        return std::nullopt;
    return PageDefinition{Constant->Sym, Constant->Offset, Insn.Page};
}

// Early value analysis intentionally precedes discovery of some unbounded
// switch-table arms. Feeding those later edges back into it would introduce a
// negation cycle. This final-CFG must-reaching check only extends a *known*
// plain ADRP expression; it never invents an address from a numeric constant.
std::optional<PageDefinition> reachingDefinition(
    const std::map<const gtirb::CodeBlock*, BlockState>& States,
    const gtirb::CodeBlock* Block, size_t End, int Register)
{
    using Position = std::pair<const gtirb::CodeBlock*, size_t>;
    std::vector<Position> Work{{Block, End}};
    std::set<Position> Visited;
    std::optional<PageDefinition> Found;
    while(!Work.empty())
    {
        auto [Current, Limit] = Work.back();
        Work.pop_back();
        if(!Visited.insert({Current, Limit}).second)
            continue;
        auto It = States.find(Current);
        if(It == States.end() || !It->second.Complete)
            return std::nullopt;
        const auto& State = It->second;
        bool Defined = false;
        for(size_t I = Limit; I > 0; --I)
        {
            const auto& Insn = State.Instructions[I - 1];
            if(Insn.Writes[Register])
            {
                auto Def = definition(*Current, Insn, Register);
                if(!Def || (Found && !(*Found == *Def)))
                    return std::nullopt;
                Found = Def;
                Defined = true;
                break;
            }
            if(Insn.Call && !(19 <= Register && Register <= 28))
                return std::nullopt;
        }
        if(Defined)
            continue;
        if(State.UnknownEntry || State.Predecessors.empty())
            return std::nullopt;
        for(const auto* Predecessor : State.Predecessors)
        {
            auto Pred = States.find(Predecessor);
            if(Pred == States.end())
                return std::nullopt;
            Work.emplace_back(Predecessor, Pred->second.Instructions.size());
        }
    }
    // A closed cycle with no establishing definition is not evidence.
    return Found;
}

// GNU ld's Cortex-A53 843419 workaround can replace a page ADRP at 0xff8
// or 0xffc with ADR. If that page lies outside an object, early symbolization
// leaves the ADR numeric and describes its tail as target - integral_page.
// Keep genuine exact ADR bases unchanged: only canonicalize this page-only
// use when every read agrees and the base is killed before leaving the block.
void restoreRelaxedPages(gtirb::Module& Module,
                         std::map<const gtirb::CodeBlock*, BlockState>& States)
{
    if(Module.getFileFormat() != gtirb::FileFormat::ELF)
        return;
    for(auto& [Block, State] : States)
    {
        if(!State.Complete)
            continue;
        for(size_t I = 0; I < State.Instructions.size(); ++I)
        {
            auto& High = State.Instructions[I];
            uint64_t WithinPage = High.Address & 4095;
            if(High.ExactRegister < 0 || (High.ExactAddress & 4095)
               || (WithinPage != 0xff8 && WithinPage != 0xffc)
               || expression(*Block, High.Address))
                continue;
            int Register = High.ExactRegister;
            gtirb::Symbol* Symbol = nullptr;
            int64_t Addend = 0;
            std::vector<size_t> Uses;
            bool Killed = false;
            for(size_t J = I + 1; J < State.Instructions.size(); ++J)
            {
                const auto& Low = State.Instructions[J];
                if(Low.Call)
                    break;
                if(Low.Reads[Register])
                {
                    const auto* Expr = expression(*Block, Low.Address);
                    const auto* Difference = Expr ? std::get_if<gtirb::SymAddrAddr>(Expr) : nullptr;
                    if(Low.LowRegister != Register || Low.LowValueReads[Register]
                       || !Difference || Difference->Scale != 1
                       || !Difference->Attributes.empty() || Difference->Sym2->hasReferent()
                       || !Difference->Sym1->getAddress() || !Difference->Sym2->getAddress()
                       || uint64_t(*Difference->Sym2->getAddress()) != High.ExactAddress
                       || uint64_t(*Difference->Sym1->getAddress()) + Difference->Offset
                              != High.ExactAddress + Low.LowOffset
                       || (Symbol && (Symbol != Difference->Sym1 || Addend != Difference->Offset)))
                        break;
                    Symbol = Difference->Sym1;
                    Addend = Difference->Offset;
                    Uses.push_back(J);
                }
                if(Low.Writes[Register])
                {
                    Killed = true;
                    break;
                }
            }
            if(!Killed || Uses.empty())
                continue;

            gtirb::SymAttributeSet HighAttributes;
            // A known forwarded GOT slot denotes the ultimate symbol for the
            // printer. Ordinary relocated pointers in .data must not acquire
            // GOT semantics merely because they contain an address.
            if(auto* Data = Symbol->getReferent<gtirb::DataBlock>())
            {
                const auto* Section = Data->getByteInterval()->getSection();
                const auto* Forwarding = Module.getAuxData<gtirb::schema::SymbolForwarding>();
                if(Section && (Section->getName() == ".got" || Section->getName() == ".got.plt")
                   && Forwarding && Forwarding->count(Symbol->getUUID()))
                {
                    // The GOT low relocation is LD64_GOT_LO12_NC. It is not
                    // valid for a 32-bit load, a store, or an address ADD.
                    if(Addend != 0 || std::any_of(Uses.begin(), Uses.end(),
                           [&](size_t J) { return !State.Instructions[J].GotLoad; }))
                        continue;
                    HighAttributes.insert(gtirb::SymAttribute::GOT);
                }
            }
            auto* Interval = const_cast<gtirb::CodeBlock*>(Block)->getByteInterval();
            uint64_t Offset = High.Address - uint64_t(*Interval->getAddress());
            int64_t Delta = int64_t(High.ExactAddress >> 12) - int64_t(High.Address >> 12);
            uint32_t Word = 0x90000000 | (uint32_t(Delta) & 3) << 29
                            | ((uint32_t(Delta) >> 2) & 0x7ffff) << 5 | Register;
            for(unsigned Byte = 0; Byte != 4; ++Byte)
                Interval->rawBytes<uint8_t>()[Offset + Byte] = (Word >> (Byte * 8)) & 255;
            Interval->addSymbolicExpression<gtirb::SymAddrConst>(
                Offset, Addend, Symbol, HighAttributes);
            auto LowAttributes = HighAttributes;
            LowAttributes.insert(gtirb::SymAttribute::LO12);
            for(size_t J : Uses)
            {
                uint64_t LowOffset = State.Instructions[J].Address - uint64_t(*Interval->getAddress());
                Interval->addSymbolicExpression<gtirb::SymAddrConst>(
                    LowOffset, Addend, Symbol, LowAttributes);
                if(auto* Sizes = Module.getAuxData<gtirb::schema::SymbolicExpressionSizes>())
                    (*Sizes)[gtirb::Offset(Interval->getUUID(), LowOffset)] = 4;
            }
            if(auto* Sizes = Module.getAuxData<gtirb::schema::SymbolicExpressionSizes>())
                (*Sizes)[gtirb::Offset(Interval->getUUID(), Offset)] = 4;
            // The same pass next visits other users; keep its decoded state
            // coherent with the changed bytes, not a stale exact ADR.
            High.PageRegister = Register;
            High.Page = High.ExactAddress;
            High.ExactRegister = -1;
        }
    }
}
} // namespace

void completeArm64PageReferences(gtirb::Module& Module)
{
    if(Module.getISA() != gtirb::ISA::ARM64 || Module.getByteOrder() != gtirb::ByteOrder::Little)
        return;
    csh Handle;
    if(cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &Handle) != CS_ERR_OK)
        return;
    cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);
    std::map<const gtirb::CodeBlock*, BlockState> States;
    for(const auto& Block : Module.code_blocks())
    {
        auto& State = States[&Block];
        if(!Block.getAddress() || !Block.getSize())
            continue;
        cs_insn* Decoded = nullptr;
        size_t Count = cs_disasm(Handle, Block.rawBytes<const uint8_t>(), Block.getSize(),
                                uint64_t(*Block.getAddress()), 0, &Decoded);
        uint64_t Bytes = 0;
        for(size_t I = 0; I < Count; ++I)
        {
            auto& Insn = Decoded[I];
            fixAArch64Capstone6Accesses(Insn);
            Instruction Info{Insn.address, {}, cs_insn_group(Handle, &Insn, CS_GRP_CALL)};
            cs_regs Read, Written;
            uint8_t ReadCount, WriteCount;
            if(cs_regs_access(Handle, &Insn, Read, &ReadCount, Written, &WriteCount) == CS_ERR_OK)
            {
                for(unsigned J = 0; J < ReadCount; ++J)
                    if(int Register = registerNumber(Handle, Read[J]); Register >= 0)
                        Info.Reads.set(Register);
                for(unsigned J = 0; J < WriteCount; ++J)
                    if(int Register = registerNumber(Handle, Written[J]); Register >= 0)
                        Info.Writes.set(Register);
            }
            else
            {
                Info.Reads.set();
                Info.Writes.set();
            }
            const auto& A = Insn.detail->aarch64;
            if(Insn.id == AARCH64_INS_ADRP && A.op_count == 2
               && A.operands[0].type == AARCH64_OP_REG && A.operands[1].type == AARCH64_OP_IMM)
            {
                Info.PageRegister = registerNumber(Handle, A.operands[0].reg);
                Info.Page = A.operands[1].imm;
            }
            if(Insn.id == AARCH64_INS_ADR && A.op_count == 2
               && A.operands[0].type == AARCH64_OP_REG && A.operands[1].type == AARCH64_OP_IMM)
            {
                Info.ExactRegister = registerNumber(Handle, A.operands[0].reg);
                Info.ExactAddress = A.operands[1].imm;
            }
            uint32_t Word = uint32_t(Insn.bytes[0]) | uint32_t(Insn.bytes[1]) << 8
                            | uint32_t(Insn.bytes[2]) << 16 | uint32_t(Insn.bytes[3]) << 24;
            Info.GotLoad = (Word & 0xffc00000) == 0xf9400000;
            // Only forms admitting an AArch64 LO12 relocation: unshifted ADD
            // Xd,Xn,#imm12 and unsigned-offset loads/stores (not pair, indexed,
            // writeback or unscaled forms). Do not turn a completed address
            // used by an ordinary load into another page expression.
            if((Word & 0xffc00000) == 0x91000000)
            {
                Info.LowRegister = (Word >> 5) & 31;
                Info.LowOffset = (Word >> 10) & 4095;
            }
            else if((Word & 0x3b000000) == 0x39000000 && !Insn.detail->writeback)
            {
                for(unsigned J = 0; J < A.op_count; ++J)
                {
                    if(A.operands[J].type == AARCH64_OP_MEM
                       && A.operands[J].mem.index == AARCH64_REG_INVALID
                       && A.operands[J].mem.disp >= 0 && A.operands[J].mem.disp < 4096)
                    {
                        Info.LowRegister = registerNumber(Handle, A.operands[J].mem.base);
                        Info.LowOffset = A.operands[J].mem.disp;
                    }
                    // A store can use the page register as both its address
                    // and its payload. That second use makes the exact ADR
                    // value observable and must not be canonicalized away.
                    if(A.operands[J].type == AARCH64_OP_REG
                       && (A.operands[J].access & CS_AC_READ))
                        if(int Register = registerNumber(Handle, A.operands[J].reg); Register >= 0)
                            Info.LowValueReads.set(Register);
                }
            }
            State.Instructions.push_back(Info);
            Bytes += Insn.size;
        }
        State.Complete = Bytes == Block.getSize();
        cs_free(Decoded, Count);
    }
    cs_close(&Handle);
    restoreRelaxedPages(Module, States);

    const auto& Cfg = Module.getIR()->getCFG();
    for(auto Edge : boost::make_iterator_range(boost::edges(Cfg)))
    {
        const auto* Destination = gtirb::dyn_cast_or_null<gtirb::CodeBlock>(Cfg[target(Edge, Cfg)]);
        auto Found = States.find(Destination);
        if(Found == States.end())
            continue;
        const auto* Source = gtirb::dyn_cast_or_null<gtirb::CodeBlock>(Cfg[source(Edge, Cfg)]);
        const auto& Label = Cfg[Edge];
        if(Label && std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Return)
            continue;
        if(Source && Label
           && (std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Branch
               || std::get<gtirb::EdgeType>(*Label) == gtirb::EdgeType::Fallthrough))
            Found->second.Predecessors.push_back(Source);
        else
            Found->second.UnknownEntry = true;
    }
    std::set<gtirb::UUID> EntryIds;
    if(const auto* Functions = Module.getAuxData<gtirb::schema::FunctionEntries>())
        for(const auto& [Function, Entries] : *Functions)
            EntryIds.insert(Entries.begin(), Entries.end());
    for(auto& [Block, State] : States)
        if(EntryIds.count(Block->getUUID()))
            State.UnknownEntry = true;

    for(const auto& [Block, State] : States)
        for(size_t I = 0; I < State.Instructions.size(); ++I)
        {
            const auto& Insn = State.Instructions[I];
            if(!State.Complete || Insn.LowRegister < 0 || Insn.LowRegister >= 31
               || expression(*Block, Insn.Address))
                continue;
            auto Def = reachingDefinition(States, Block, I, Insn.LowRegister);
            if(!Def || Def->Page + Insn.LowOffset
                           != uint64_t(*Def->Symbol->getAddress()) + Def->Addend)
                continue;
            // Module owns the blocks; mutable interval lookup is safe here.
            auto* Interval = const_cast<gtirb::CodeBlock*>(Block)->getByteInterval();
            uint64_t Offset = Insn.Address - uint64_t(*Interval->getAddress());
            Interval->addSymbolicExpression<gtirb::SymAddrConst>(
                Offset, Def->Addend, Def->Symbol, gtirb::SymAttributeSet{gtirb::SymAttribute::LO12});
            if(auto* Sizes = Module.getAuxData<gtirb::schema::SymbolicExpressionSizes>())
                (*Sizes)[gtirb::Offset(Interval->getUUID(), Offset)] = 4;
        }
}
