//===-- arm-unwind-dump.cpp - ARM Unwind Opcode Tool ----------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This is a testing tool for ARM ELF EHABI unwind opcodes.
//
//===----------------------------------------------------------------------===//

#include <llvm/ADT/OwningPtr.h>
#include <llvm/Object/ELF.h>
#include <llvm/Object/ObjectFile.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Endian.h>
#include <llvm/Support/Format.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/system_error.h>

#include <algorithm>
#include <vector>

#include <stdlib.h>

using namespace llvm;
using namespace llvm::object;

namespace {

cl::opt<std::string> InputFile(
  cl::Positional, cl::desc("<input file>"), cl::init("-"));

bool IsError(error_code EC) {
  if (!EC) return false;
  errs() << "ERROR: " << EC.message() << "\n";
  errs().flush();
  return true;
}

void Ensure(error_code EC) {
  if (IsError(EC)) {
    exit(EXIT_FAILURE);
  }
}

bool DecodeULEB128(uint64_t &Result, unsigned &Len,
                   const std::vector<uint8_t> &Data, size_t Begin) {
  size_t Pos = Begin;
  unsigned Shift = 0;
  uint64_t Value = 0;

  do {
    if (Pos >= Data.size()) {
      return false;
    }
    Value += (Data[Pos] & 0x7fu) << Shift;
    Shift += 7;
  } while (Data[Pos++] >= 128);

  Result = Value;
  Len = Pos - Begin;
  return true;
}

void DumpHex(formatted_raw_ostream &OS, const std::vector<uint8_t> &Data) {
  size_t size = Data.size();
  for (size_t i = 0; i < size; i += 16) {
    OS << format("%08zx | ", i);
    for (size_t j = i, n = std::min(j + 16, size); j < n; ++j) {
      OS << format(" %02x", static_cast<unsigned>(Data[j]));
    }
    OS << "\n";
  }
}

} // end anonymous namespace

typedef ELFType<support::little, 4, false> ARM_ELFType;
typedef ELFObjectFile<ARM_ELFType>         ARM_ELFObjectFile;
typedef Elf_Shdr_Impl<ARM_ELFType>         ARM_ELF_Shdr;
typedef Elf_Sym_Impl<ARM_ELFType>          ARM_ELF_Sym;
typedef Elf_Dyn_Impl<ARM_ELFType>          ARM_ELF_Dyn;
typedef Elf_Rel_Impl<ARM_ELFType, false>   ARM_ELF_Rel;
typedef Elf_Rel_Impl<ARM_ELFType, true>    ARM_ELF_Rela;

class ARMUnwindOpcodesDisassembler {
private:
  ARM_ELFObjectFile &ObjFile;
  formatted_raw_ostream &OS;

public:
  ARMUnwindOpcodesDisassembler(ARM_ELFObjectFile &ObjFile_,
                               formatted_raw_ostream &OS_);

  void Dump();

private:
  section_iterator getSection(size_t i);

  symbol_iterator getSymbol(section_iterator Section,
                            uint64_t Offset,
                            SymbolRef::Type Ty);

  relocation_iterator getRelocation(section_iterator Section,
                                    uint64_t Offset,
                                    uint64_t Type);

  void DumpSections();
  void DumpSection(section_iterator Section);
  void DumpExIdxEntries(section_iterator Section);
  void DumpExIdxEntry(section_iterator Section,
                      StringRef Contents,
                      uint64_t Offset);

  void DecodeOpcodes(const std::vector<uint8_t> &Opcodes);

  // vsp = vsp + (a << 2) + 4
  void Decode_00aaaaaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // vsp = vsp - (a << 2) - 4
  void Decode_01aaaaaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // refuse unwind
  void Decode_10000000_00000000(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop r[4-15]
  void Decode_1000aaaa_bbbbbbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // vsp = r[a]
  void Decode_1001aaaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // arm reg-to-reg move
  void Decode_10011101(llvm::raw_ostream &OS, uint16_t Opcode);

  // intel wireless reg-to-reg move
  void Decode_10011111(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop r[4-(4+a)]
  void Decode_10100aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop r[4-(4+a)], r14
  void Decode_10101aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // finish
  void Decode_10110000(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_10110001_00000000(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop r[0-3]
  void Decode_10110001_0000aaaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_10110001_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop d[a-(a+b)]
  void Decode_10110011_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_101101aa(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop d[8-(8+a)]
  void Decode_10111aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop wR[10-(10+a)]
  void Decode_11000aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop wR[a-(a+b)]
  void Decode_11000110_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_11000111_00000000(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop wR[0-3]
  void Decode_11000111_0000aaaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_11000111_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop d[(16+a)-(16+a+b)]
  void Decode_11001000_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop d[a-(a+b)]
  void Decode_11001001_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_11001aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // pop d[8-(8+a)]
  void Decode_11010aaa(llvm::raw_ostream &OS, uint16_t Opcode);

  // spare
  void Decode_11aaabbb(llvm::raw_ostream &OS, uint16_t Opcode);

  // vsp = vsp + (value << 2) + 0x204
  void Decode_10110010(llvm::raw_ostream &OS,
                       const uint8_t *Opcodes,
                       uint64_t Value,
                       unsigned Len);

  void PrintRegMask(llvm::raw_ostream &OS,
                    const char *RegClass,
                    uint32_t Mask);

  void PrintRegRange(llvm::raw_ostream &OS,
                     const char *RegClass,
                     uint32_t Begin,
                     uint32_t Range);
};

ARMUnwindOpcodesDisassembler::
ARMUnwindOpcodesDisassembler(ARM_ELFObjectFile &ObjFile_,
                             formatted_raw_ostream &OS_)
  : ObjFile(ObjFile_), OS(OS_) {
}

section_iterator ARMUnwindOpcodesDisassembler::getSection(size_t i) {
  error_code EC;
  section_iterator SI = ObjFile.begin_sections();
  section_iterator SE = ObjFile.end_sections();
  while (SI != SE && i > 0) {
    SI.increment(EC);
    Ensure(EC);
    --i;
  }
  return SI;
}

symbol_iterator ARMUnwindOpcodesDisassembler::
getSymbol(section_iterator Section, uint64_t Offset, SymbolRef::Type Ty) {
  error_code EC;
  for (symbol_iterator SYMI = ObjFile.begin_symbols(),
       SYME = ObjFile.end_symbols(); SYMI != SYME; SYMI.increment(EC)) {
    Ensure(EC);

    section_iterator SYMISection(ObjFile.end_sections());
    uint64_t SYMIOffset;
    SymbolRef::Type SYMIType;

    Ensure(SYMI->getSection(SYMISection));
    Ensure(SYMI->getValue(SYMIOffset));
    Ensure(SYMI->getType(SYMIType));

    if (Section == SYMISection && Offset == SYMIOffset && Ty == SYMIType) {
      return SYMI;
    }
  }
  return ObjFile.end_symbols();
}

relocation_iterator ARMUnwindOpcodesDisassembler::
getRelocation(section_iterator Section, uint64_t Offset, uint64_t Type) {
  error_code EC;
  for (relocation_iterator RI = Section->begin_relocations(),
       RE = Section->end_relocations(); RI != RE; RI.increment(EC)) {
    Ensure(EC);

    uint64_t RIOffset, RIType;
    Ensure(RI->getOffset(RIOffset));
    Ensure(RI->getType(RIType));

    if (Offset == RIOffset && Type == RIType) {
      return RI;
    }
  }
  return Section->end_relocations();
}

void ARMUnwindOpcodesDisassembler::Dump() {
  DumpSections();
}

void ARMUnwindOpcodesDisassembler::DumpSections() {
  error_code EC;
  if (ObjFile.getNumSections() > 0) {
    section_iterator SI = ObjFile.begin_sections();
    section_iterator SE = ObjFile.end_sections();

    DumpSection(SI);
    SI.increment(EC);
    Ensure(EC);

    for (; SI != SE; SI.increment(EC)) {
      Ensure(EC);
      OS << "\n";
      DumpSection(SI);
    }
  }
}

void ARMUnwindOpcodesDisassembler::DumpSection(section_iterator Section) {
  // Dump section name
  StringRef Name;
  Ensure(Section->getName(Name));
  OS << "- section: " << Name << "\n";

  // Dump section flags and linked section
  const ARM_ELF_Shdr *Shdr = ObjFile.getElfSection(Section);
  uint32_t sh_flags = Shdr->sh_flags;
  uint32_t sh_link = Shdr->sh_link;

  OS << "  flag: " << format("%08"PRIx32, sh_flags) << "\n";
  OS << "  link: " << format("%08"PRIx32, sh_link);
  if (sh_link != 0) {
    section_iterator LinkSec(getSection(sh_link));
    StringRef LinkSecName;
    Ensure(LinkSec->getName(LinkSecName));
    OS << " \"" << LinkSecName << "\"";
  }
  OS << "\n";

  // Dump exception handling entries (if this is .ARM.exidx)
  if (Shdr->sh_type == ELF::SHT_ARM_EXIDX) {
    DumpExIdxEntries(Section);
  }
}

void ARMUnwindOpcodesDisassembler::DumpExIdxEntries(section_iterator Section) {
  StringRef Contents;
  Ensure(Section->getContents(Contents));

  if (Contents.size() % 8 != 0) {
    errs() << "ERROR: Content size does not align to 8\n";
    exit(EXIT_FAILURE);
  }

  OS << "  entries:\n";
  for (size_t i = 0; i < Contents.size(); i += 8) {
    DumpExIdxEntry(Section, Contents, i);
  }
}

void ARMUnwindOpcodesDisassembler::DumpExIdxEntry(section_iterator Section,
                                                  StringRef Contents,
                                                  uint64_t Offset) {
  const uint32_t *Data =
    reinterpret_cast<const uint32_t *>(Contents.data() + Offset);

  relocation_iterator FuncReloc(
    getRelocation(Section, Offset, ELF::R_ARM_PREL31));

  if (FuncReloc == Section->end_relocations()) {
    OS << "  - function: <unknown>+0x" << format("%"PRIx32, Data[0]) << "\n";
  } else {
    // Get the referee symbol
    SymbolRef Sym;
    int64_t Addend;
    Ensure(FuncReloc->getSymbol(Sym));
    Ensure(FuncReloc->getAdditionalInfo(Addend));
    Addend += static_cast<int32_t>(Data[0]);

    // Get the symbol offset to the section containing the symbol
    section_iterator SymSection(ObjFile.end_sections());
    uint64_t SymOffset;
    Ensure(Sym.getSection(SymSection));
    Ensure(Sym.getValue(SymOffset));

    // Backward search for the function symbol
    symbol_iterator FuncSym(getSymbol(SymSection, SymOffset + Addend,
                                      SymbolRef::ST_Function));
    OS << "  - function: ";
    StringRef Name;
    if (FuncSym != ObjFile.end_symbols()) {
      Ensure(FuncSym->getName(Name));
      OS << Name;
    } else {
      Ensure(Sym.getName(Name));
      OS << Name;
      if (Addend > 0) {
        OS << "+0x" << format("%"PRIx32, static_cast<int32_t>(Addend));
      } else if (Addend < 0) {
        OS << "-0x" << format("%"PRIx32, static_cast<int32_t>(-Addend));
      }
    }
    OS << "\n";
  }

  relocation_iterator DataReloc(
    getRelocation(Section, Offset + 4, ELF::R_ARM_PREL31));

  StringRef Personality;
  std::vector<uint8_t> Opcodes;

  if (DataReloc == Section->end_relocations()) {
    if (Data[1] == 0x00000001u) {
      OS << "    cant_unwind: 1\n";
    } else {
      Personality = "__aeabi_unwind_cpp_pr0";
      Opcodes.push_back((Data[1] >> 16) & 0xff);
      Opcodes.push_back((Data[1] >> 8) & 0xff);
      Opcodes.push_back((Data[1]) & 0xff);

      OS << "    personality: " << Personality << "\n";
      OS << "    unwind_opcodes: |\n";
      DecodeOpcodes(Opcodes);
    }
  } else {
    // Get the referee symbol
    SymbolRef Sym;
    int64_t Addend;
    Ensure(DataReloc->getSymbol(Sym));
    Ensure(DataReloc->getAdditionalInfo(Addend));
    Addend += static_cast<int32_t>(Data[1]);

    // Get the symbol offset to the section containing the symbol
    section_iterator SymSection(ObjFile.end_sections());
    uint64_t SymOffset;
    Ensure(Sym.getSection(SymSection));
    Ensure(Sym.getValue(SymOffset));

    // Get the contents of the section
    StringRef Contents;
    Ensure(SymSection->getContents(Contents));

    const uint32_t *Data =
      reinterpret_cast<const uint32_t *>(Contents.data() + SymOffset + Addend);

    size_t Size = 0;
    unsigned MSB = (Data[0] >> 24) & 0xffu;
    if (MSB == 0x80u) {
      Personality = "__aeabi_unwind_cpp_pr0";
      Opcodes.push_back((Data[0] >> 16) & 0xff);
      Opcodes.push_back((Data[0] >> 8) & 0xff);
      Opcodes.push_back((Data[0]) & 0xff);
    } else if (MSB == 0x81u || MSB == 0x82u) {
      Personality = (MSB == 0x81u) ? "__aeabi_unwind_cpp_pr1"
                                   : "__aeabi_unwind_cpp_pr2";
      Size = ((Data[0] >> 16) & 0xffu) + 1;

      Opcodes.push_back((Data[0] >> 8) & 0xff);
      Opcodes.push_back((Data[0]) & 0xff);

      for (size_t i = 1; i < Size; ++i) {
        Opcodes.push_back((Data[i] >> 24) & 0xff);
        Opcodes.push_back((Data[i] >> 16) & 0xff);
        Opcodes.push_back((Data[i] >> 8) & 0xff);
        Opcodes.push_back((Data[i]) & 0xff);
      }
    } else {
      Size = ((Data[1] >> 24) & 0xffu) + 2;

      relocation_iterator PersonalityReloc(
        getRelocation(SymSection, SymOffset + Addend, ELF::R_ARM_PREL31));

      if (PersonalityReloc == SymSection->end_relocations()) {
        Personality = "<< no relocation for personality >>";
      } else {
        SymbolRef PersonalitySym;
        Ensure(PersonalityReloc->getSymbol(PersonalitySym));
        PersonalitySym.getName(Personality);
      }

      Opcodes.push_back((Data[1] >> 16) & 0xff);
      Opcodes.push_back((Data[1] >> 8) & 0xff);
      Opcodes.push_back((Data[1]) & 0xff);

      for (size_t i = 2; i < Size; ++i) {
        Opcodes.push_back((Data[i] >> 24) & 0xff);
        Opcodes.push_back((Data[i] >> 16) & 0xff);
        Opcodes.push_back((Data[i] >> 8) & 0xff);
        Opcodes.push_back((Data[i]) & 0xff);
      }
    }

    OS << "    personality: " << Personality << "\n";
    OS << "    unwind_opcodes: |\n";
    DecodeOpcodes(Opcodes);
  }
}

void ARMUnwindOpcodesDisassembler::
DecodeOpcodes(const std::vector<uint8_t> &Opcodes) {
  size_t i = 0;

  std::vector<std::string> HexColumn;
  std::vector<std::string> AsmColumn;

  while (i < Opcodes.size()) {
    HexColumn.push_back(std::string());
    AsmColumn.push_back(std::string());
    raw_string_ostream HexOS(HexColumn.back());
    raw_string_ostream AsmOS(AsmColumn.back());

    HexOS << format("%02x", static_cast<unsigned>(Opcodes[i]));
    uint16_t Op = Opcodes[i++];

#define FETCH_NEXT_BYTE() \
    do { \
      if (i >= Opcodes.size()) { \
        AsmOS << "Bad instruction sequence"; \
        break; \
      } \
      HexOS << format(" %02x", static_cast<unsigned>(Opcodes[i])); \
      Op = (Op << 8) | Opcodes[i++]; \
    } while (0)

    // NOTE: Check ARM EHABI page 41-42 for unwind opcode decoding table:
    //  http://infocenter.arm.com/help/topic/com.arm.doc.ihi0038a/
    //  IHI0038A_ehabi.pdf

    if ((Op & 0xc0u) == 0x00u) {
      Decode_00aaaaaa(AsmOS, Op);
    } else if ((Op & 0xc0u) == 0x40u) {
      Decode_01aaaaaa(AsmOS, Op);
    } else if (Op == 0x80u) {
      FETCH_NEXT_BYTE();
      if ((Op & 0xffu) == 0x00u) {
        Decode_10000000_00000000(AsmOS, Op);
      } else {
        Decode_1000aaaa_bbbbbbbb(AsmOS, Op);
      }
    } else if ((Op & 0xf0u) == 0x80u) {
      FETCH_NEXT_BYTE();
      Decode_1000aaaa_bbbbbbbb(AsmOS, Op);
    } else if ((Op & 0xf0u) == 0x90u) {
      if (Op == 0x9du) {
        Decode_10011101(AsmOS, Op);
      } else if (Op == 0x9fu) {
        Decode_10011111(AsmOS, Op);
      } else {
        Decode_1001aaaa(AsmOS, Op);
      }
    } else if ((Op & 0xf8u) == 0xa0u) {
      Decode_10100aaa(AsmOS, Op);
    } else if ((Op & 0xf8u) == 0xa8u) {
      Decode_10101aaa(AsmOS, Op);
    } else if (Op == 0xb0u) {
      Decode_10110000(AsmOS, Op);
    } else if (Op == 0xb1u) {
      FETCH_NEXT_BYTE();
      if ((Op & 0xffu) == 0x00u) {
        Decode_10110001_00000000(AsmOS, Op);
      } else if ((Op & 0xf0u) == 0x00u) {
        Decode_10110001_0000aaaa(AsmOS, Op);
      } else {
        Decode_10110001_aaaabbbb(AsmOS, Op);
      }
    } else if (Op == 0xb2u) {
      uint64_t Value = 0u;
      unsigned Len = 0u;
      if (!DecodeULEB128(Value, Len, Opcodes, i)) {
        AsmOS << "Bad instruction sequence";
        break;
      }
      for (size_t j = 0; j < Len; ++j) {
        HexOS << format(" %02x", static_cast<unsigned>(Opcodes[i + j]));
      }
      Decode_10110010(AsmOS, &*Opcodes.begin() + i - 1, Value, Len);
      i += Len;
    } else if (Op == 0xb3u) {
      FETCH_NEXT_BYTE();
      Decode_10110011_aaaabbbb(AsmOS, Op);
    } else if ((Op & 0xfcu) == 0xb4u) {
      Decode_101101aa(AsmOS, Op);
    } else if ((Op & 0xf8u) == 0xb8u) {
      Decode_10111aaa(AsmOS, Op);
    } else if (Op == 0xc6u) {
      FETCH_NEXT_BYTE();
      Decode_11000110_aaaabbbb(AsmOS, Op);
    } else if (Op == 0xc7u) {
      FETCH_NEXT_BYTE();
      if ((Op & 0xffu) == 0x00u) {
        Decode_11000111_00000000(AsmOS, Op);
      } else if ((Op & 0xf0u) == 0x00u) {
        Decode_11000111_0000aaaa(AsmOS, Op);
      } else {
        Decode_11000111_aaaabbbb(AsmOS, Op);
      }
    } else if ((Op & 0xf8u) == 0xc0u) {
      Decode_11000aaa(AsmOS, Op);
    } else if (Op == 0xc8u) {
      FETCH_NEXT_BYTE();
      Decode_11001000_aaaabbbb(AsmOS, Op);
    } else if (Op == 0xc9u) {
      FETCH_NEXT_BYTE();
      Decode_11001001_aaaabbbb(AsmOS, Op);
    } else if ((Op & 0xf8u) == 0xc8u) {
      Decode_11001aaa(AsmOS, Op);
    } else if ((Op & 0xf8u) == 0xd0u) {
      Decode_11010aaa(AsmOS, Op);
    } else if ((Op & 0xc0u) == 0xc0u) {
      Decode_11aaabbb(AsmOS, Op);
    } else {
      assert(0 && "Unexpected cases");
    }
#undef FETCH_NEXT_BYTE
  }

  size_t ColumnWidth = 0;
  for (size_t i = 0; i < HexColumn.size(); ++i) {
    ColumnWidth = std::max(ColumnWidth, HexColumn[i].size());
  }

  for (size_t i = 0; i < HexColumn.size(); ++i) {
    OS.PadToColumn(6);
    OS << HexColumn[i];
    OS.PadToColumn(7 + ColumnWidth);
    OS << "| ";
    OS << AsmColumn[i];
    OS << "\n";
  }
}

void ARMUnwindOpcodesDisassembler::Decode_00aaaaaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  uint16_t Offset = ((Opcode & 0x3fu) << 2) + 4;
  OS << "vsp = vsp + " << Offset;
}

void ARMUnwindOpcodesDisassembler::Decode_01aaaaaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  uint16_t Offset = ((Opcode & 0x3fu) << 2) + 4;
  OS << "vsp = vsp - " << Offset;
}

void ARMUnwindOpcodesDisassembler::
Decode_10000000_00000000(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "refuse to unwind";
}

void ARMUnwindOpcodesDisassembler::
Decode_1000aaaa_bbbbbbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Mask = (Opcode & 0x0fffu) << 4;
  PrintRegMask(OS, "r", Mask);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_1001aaaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  uint16_t Reg = Opcode & 0x0fu;
  OS << "vsp = r" << Reg;
}

void ARMUnwindOpcodesDisassembler::Decode_10011101(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "reserved for ARM reg-to-reg move";
}

void ARMUnwindOpcodesDisassembler::Decode_10011111(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "reserved for Intel wireless reg-to-reg move";
}

void ARMUnwindOpcodesDisassembler::Decode_10100aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "pop {";
  uint16_t Range = Opcode & 0x07u;
  PrintRegRange(OS, "r", 4, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_10101aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "pop {";
  uint16_t Range = Opcode & 0x07u;
  PrintRegRange(OS, "r", 4, Range);
  OS << ", r14}";
}

void ARMUnwindOpcodesDisassembler::Decode_10110000(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "finish";
}

void ARMUnwindOpcodesDisassembler::
Decode_10110001_00000000(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::
Decode_10110001_0000aaaa(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Mask = Opcode & 0x0fu;
  PrintRegMask(OS, "r", Mask);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::
Decode_10110001_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::
Decode_10110011_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Begin = (Opcode & 0xf0u) >> 4;
  uint16_t Range = (Opcode & 0x0fu);
  PrintRegRange(OS, "d", Begin, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_101101aa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::Decode_10111aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "pop {";
  uint16_t Range = Opcode & 0x07u;
  PrintRegRange(OS, "d", 8, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_11000aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "pop {";
  uint16_t Range = Opcode & 0x07u;
  PrintRegRange(OS, "wR", 10, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::
Decode_11000110_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Begin = (Opcode & 0xf0u) >> 4;
  uint16_t Range = (Opcode & 0x0fu);
  PrintRegRange(OS, "wR", Begin, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::
Decode_11000111_00000000(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::
Decode_11000111_0000aaaa(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Mask = Opcode & 0x0fu;
  PrintRegMask(OS, "wR", Mask);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::
Decode_11000111_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::
Decode_11001000_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Begin = (Opcode & 0xf0u) >> 4;
  uint16_t Range = (Opcode & 0x0fu);
  PrintRegRange(OS, "d", 16 + Begin, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::
Decode_11001001_aaaabbbb(llvm::raw_ostream &OS, uint16_t Opcode) {
  OS << "pop {";
  uint16_t Begin = (Opcode & 0xf0u) >> 4;
  uint16_t Range = (Opcode & 0x0fu);
  PrintRegRange(OS, "d", Begin, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_11001aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::Decode_11010aaa(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "pop {";
  uint16_t Range = Opcode & 0x07u;
  PrintRegRange(OS, "d", 8, Range);
  OS << "}";
}

void ARMUnwindOpcodesDisassembler::Decode_11aaabbb(llvm::raw_ostream &OS,
                                                   uint16_t Opcode) {
  OS << "spare";
}

void ARMUnwindOpcodesDisassembler::Decode_10110010(llvm::raw_ostream &OS,
                                                   const uint8_t *Opcodes,
                                                   uint64_t Value,
                                                   unsigned Len) {
  uint64_t Offset = (Value << 2) + 0x204u;
  OS << "vsp = vsp + " << Offset;
}

void ARMUnwindOpcodesDisassembler::PrintRegMask(llvm::raw_ostream &OS,
                                                const char *RegClass,
                                                uint32_t Mask) {
  bool PrintSep = false;
  for (uint32_t R = 0, B = 1u; R < 32; ++R, B <<= 1) {
    if (Mask & B) {
      if (PrintSep) {
        OS << ", ";
      } else {
        PrintSep = true;
      }
      OS << RegClass << R;
    }
  }
}

void ARMUnwindOpcodesDisassembler::PrintRegRange(llvm::raw_ostream &OS,
                                                 const char *RegClass,
                                                 uint32_t Begin,
                                                 uint32_t Range) {
  bool PrintSep = false;
  for (uint32_t R = Begin, End = Begin + Range + 1; R < End; ++R) {
    if (PrintSep) {
      OS << ", ";
    } else {
      PrintSep = true;
    }
    OS << RegClass << R;
  }
}

int main(int argc, char **argv) {
  // Read command line options
  cl::ParseCommandLineOptions(argc, argv);

  // Load the input file to memory buffer
  OwningPtr<MemoryBuffer> MemBuf;
  Ensure(MemoryBuffer::getFileOrSTDIN(InputFile, MemBuf));

  // Open the object file
  OwningPtr<ObjectFile> ObjFile(ObjectFile::createObjectFile(MemBuf.take()));
  if (!ObjFile) {
    errs() << "ERROR: Failed to load the input object file\n";
    exit(EXIT_FAILURE);
  }

  ARM_ELFObjectFile *ARMObjFile = dyn_cast<ARM_ELFObjectFile>(ObjFile.get());
  if (!ARMObjFile) {
    errs() << "ERROR: The input object file is not an ARM ELF object file\n";
    exit(EXIT_FAILURE);
  }

  // Create ARMUnwindOpcodesDisassembler
  formatted_raw_ostream OS(outs(), false);
  ARMUnwindOpcodesDisassembler DisAsm(*ARMObjFile, OS);
  DisAsm.Dump();

  return EXIT_SUCCESS;
}
