// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef SRC_PASSES_ARM64PAGEREFERENCES_H
#define SRC_PASSES_ARM64PAGEREFERENCES_H

#include <gtirb/gtirb.hpp>

// Complete page operands using the final CFG, after late jump-table discovery.
void completeArm64PageReferences(gtirb::Module& Module);

#endif
