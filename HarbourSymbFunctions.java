//Search whole memory for HB_SYMB[] and create/rename functions accordingly
//@author Christoph Brill <opensource@christophbrill.de>
//@category Analysis
//@keybinding
//@menupath Harbour
//@toolbar 
//@runtime Java

/*
 * Harbour Decomp
 * Copyright (C) 2025 Christoph Brill <opensource@christophbrill.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;

import java.nio.charset.StandardCharsets;

public class HarbourSymbFunctions extends GhidraScript {

    private static final int MAX_NAME_LEN = 256;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No active program.");
            return;
        }

        // Ensure this is run on a 32-bit program
        int ptrSize = currentProgram.getDefaultPointerSize();
        if (ptrSize != 4) {
            printerr("This script currently expects a 32-bit program (pointer size 4). Detected pointer size: %d".formatted(ptrSize));
            return;
        }

        // Get the HB_SYMB data type
        CategoryPath path = new CategoryPath("/harbour/hbvmpub.h");
        DataType hbSymb = currentProgram.getDataTypeManager().getDataType(path, "HB_SYMB");
        if (hbSymb == null) {
            printerr("Failed to find HB_SYMB data type.");
            return;
        }

        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        long symbElementsSeen = 0;
        long symbElementsUsed = 0;
        long created = 0;
        long renamed = 0;

        DataIterator it = listing.getDefinedData(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            if (d == null) {
                continue;
            }

            DataType dt = d.getDataType();
            if (dt == null) {
                continue;
            }

            if (dt.isEquivalent(hbSymb)) {
                symbElementsSeen++;
                long[] delta = processSymbElement(mem, d);
                symbElementsUsed += delta[0];
                created += delta[1];
                renamed += delta[2];
                continue;
            }

            if (dt instanceof Array arr && arr.getDataType() != null && arr.getDataType().isEquivalent(hbSymb)) {
                int n = d.getNumComponents();
                for (int i = 0; i < n && !monitor.isCancelled(); i++) {
                    Data el = d.getComponent(i);
                    if (el == null) {
                        continue;
                    }
                    if (el.getDataType() == null || !el.getDataType().isEquivalent(hbSymb)) {
                        continue;
                    }
                    symbElementsSeen++;
                    long[] delta = processSymbElement(mem, el);
                    symbElementsUsed += delta[0];
                    created += delta[1];
                    renamed += delta[2];
                }
            }
        }

        println("HB_SYMB elements seen (typed): %d".formatted(symbElementsSeen));
        println("HB_SYMB elements used (valid szName+value): %d".formatted(symbElementsUsed));
        println("Created functions: %d".formatted(created));
        println("Renamed functions: %d".formatted(renamed));
    }

    private long[] processSymbElement(Memory mem, Data symb) {

        Address szNamePtr = readStructPointerField(symb, "szName");
        Address valuePtr = readStructPointerField(symb, "value");
        if (szNamePtr == null || valuePtr == null) {
            return new long[]{0, 0, 0};
        }

        String name = readCString(mem, szNamePtr, MAX_NAME_LEN);
        if (name == null) {
            return new long[]{0, 0, 0};
        }

        String cleaned = stripQuotes(name);
        if (cleaned == null || cleaned.isBlank()) {
            return new long[]{0, 0, 0};
        }

        MemoryBlock valueBlock = mem.getBlock(valuePtr);
        if (valueBlock == null || !valueBlock.isExecute()) {
            return new long[]{0, 0, 0};
        }

        // returns {used, created, renamed}
        long used = 1;
        long created = 0;
        long renamed = 0;

        Function f = getFunctionAt(valuePtr);
        if (f == null) {
            try {
                ensureDisassemblyAt(valuePtr);
                f = createFunction(valuePtr, cleaned);
                if (f != null) {
                    created++;
                    println("Created function at %s (%s)".formatted(valuePtr, cleaned));
                }
            } catch (Exception e) {
                printerr("Failed to create function at %s (%s): %s".formatted(valuePtr, cleaned, e.getMessage()));
                return new long[]{used, created, renamed};
            }
        }

        if (f != null) {
            String existing = f.getName();
            if (!cleaned.equals(existing)) {
                try {
                    f.setName(cleaned, SourceType.USER_DEFINED);
                    renamed++;
                    println("Renamed function at %s from %s to %s".formatted(valuePtr, existing, cleaned));
                } catch (Exception e) {
                    printerr("Failed to rename function at %s from %s to %s: %s".formatted(valuePtr, existing, cleaned, e.getMessage()));
                }
            }
        }

        return new long[]{used, created, renamed};
    }

    private Address readStructPointerField(Data structData, String fieldName) {
        if (structData == null || fieldName == null) {
            return null;
        }
        int n = structData.getNumComponents();
        for (int i = 0; i < n; i++) {
            Data c = structData.getComponent(i);
            if (c == null) {
                continue;
            }
            String fn = c.getFieldName();
            if (!fieldName.equals(fn)) {
                continue;
            }
            Object v = c.getValue();
            if (v instanceof Address a) {
                return a;
            }
            if (v instanceof Number num) {
                long raw = num.longValue();
                if (raw == 0) {
                    return null;
                }
                return toAddr(raw);
            }

            // Fallback: read as 32-bit pointer from the field's address
            try {
                Address addr = c.getAddress();
                long raw = readU32(currentProgram.getMemory(), addr);
                if (raw == 0) {
                    return null;
                }
                return toAddr(raw);
            } catch (Exception ignored) {
                return null;
            }
        }
        return null;
    }

    private long readU32(Memory mem, Address addr) {
        try {
            int b0 = mem.getByte(addr) & 0xff;
            int b1 = mem.getByte(addr.add(1L)) & 0xff;
            int b2 = mem.getByte(addr.add(2L)) & 0xff;
            int b3 = mem.getByte(addr.add(3L)) & 0xff;
            int v = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            return Integer.toUnsignedLong(v);
        } catch (MemoryAccessException e) {
            return 0;
        }
    }

    private String readCString(Memory mem, Address addr, int maxLen) {
        if (addr == null) {
            return null;
        }
        MemoryBlock b = mem.getBlock(addr);
        if (b == null || !b.isInitialized()) {
            return null;
        }

        byte[] buf = new byte[maxLen];
        int n = 0;
        Address cur = addr;
        while (n < maxLen && cur != null) {
            try {
                byte v = mem.getByte(cur);
                if (v == 0) {
                    break;
                }
                if (v < 0x20 || v > 0x7e) {
                    return null;
                }
                buf[n++] = v;
                cur = cur.add(1L);
            } catch (Exception e) {
                return null;
            }
        }

        if (n == 0) {
            return null;
        }
        return new String(buf, 0, n, StandardCharsets.US_ASCII);
    }

    private String stripQuotes(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        if (t.length() >= 2) {
            if ((t.startsWith("\"") && t.endsWith("\"")) || (t.startsWith("'") && t.endsWith("'"))) {
                t = t.substring(1, t.length() - 1);
            }
        }
        return t.trim();
    }

    private void ensureDisassemblyAt(Address entry) {
        Listing listing = currentProgram.getListing();
        Instruction i = listing.getInstructionAt(entry);
        if (i != null) {
            return;
        }
        try {
            disassemble(entry);
        } catch (Exception ignored) {
            // Best effort only
        }
    }
}
