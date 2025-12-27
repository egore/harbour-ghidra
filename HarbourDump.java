//Print the Harbour P-code
//@author Christoph Brill <opensource@christophbrill.de>
//@category Analysis
//@keybinding
//@menupath Harbour P-code
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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Stack;

public class HarbourDump extends GhidraScript {

    private static class StackItem {
        final String type;
        final String value;
        final String source;

        StackItem(String type, String value, String source) {
            this.type = type;
            this.value = value;
            this.source = source;
        }

        @Override
        public String toString() {
            return "%s(%s)".formatted(type, value);
        }
    }

    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("No active program.");
            return;
        }

        Address addr = currentAddress;
        if (addr == null) {
            printerr("No current address (place the cursor in the Listing view and re-run).");
            return;
        }

        // Initialize HB_PCODE cache once per script run
        Map<Integer, String> hbPcodeCache = initializeHbPcodeCache();

        // Initialize stack simulation
        Stack<StackItem> stack = new Stack<>();

        // Fallback: If we never find a HB_P_RETVAL or HB_P_ENDPROC, we stop at the next label
        Address nextLabelAddr = findNextLabelAfter(addr);

        Memory mem = currentProgram.getMemory();
        Address maxAddr = currentProgram.getMaxAddress();

        Address cur = addr;
        while (cur != null && cur.compareTo(maxAddr) <= 0) {
            if (nextLabelAddr != null && cur.compareTo(nextLabelAddr) >= 0) {
                println("Stopping at next label boundary: %s".formatted(nextLabelAddr));
                break;
            }

            int opcode;
            try {
                opcode = mem.getByte(cur) & 0xff;
            } catch (MemoryAccessException e) {
                printerr("Unable to read memory at %s: %s".formatted(cur, e.getMessage()));
                break;
            }

            String enumLabel = hbPcodeCache.get(opcode);
            if (enumLabel == null) {
                printerr("%s: 0x%02X (%d) => HB_PCODE.<unknown> | Stack: %s".formatted(cur, opcode, opcode, stack));
                cur = cur.add(1L);
                continue;
            }

            // Process opcode with stack simulation
            cur = processOpcode(cur, opcode, enumLabel, stack, mem);

            if ("HB_P_RETVALUE".equals(enumLabel) || "HB_P_ENDPROC".equals(enumLabel)) {
                println("Stopping at terminator opcode: %s".formatted(enumLabel));
                break;
            }

            if (cur == null) {
                println("Reached end of address space during processing");
                break;
            }
        }
    }

    private Address processOpcode(Address cur, int opcode, String enumLabel, Stack<StackItem> stack, Memory mem) throws MemoryAccessException {
        //println("%s: 0x%02X (%d) => HB_PCODE.%s (len=%d) | Stack: %s".formatted(cur, opcode, opcode, enumLabel, len, stack));

        DataType dt = resolveDataTypeByName(enumLabel);
        if (dt == null) {
            printerr("Unable to resolve datatype for %s".formatted(enumLabel));
            return cur.add(1);
        }

        switch (enumLabel) {
            case "HB_P_ENDPROC":
                stack.clear();
                return cur.add(1);
            case "HB_P_FRAME":
                stack.push(new StackItem("frame", "frame", "HB_P_FRAME"));
                return cur.add(dt.getLength());
            case "HB_P_FUNCTIONSHORT":
                stack.push(new StackItem("function", "function", enumLabel));
                int functionId = mem.getByte(cur.add(1)) & 0xff;
                println("  symbols_table[%d]()".formatted(functionId - 1));
                return cur.add(dt.getLength());
            case "HB_P_LOCALNEARSETSTR":
                int lenLo = mem.getByte(cur.add(2)) & 0xff;
                int lenHi = mem.getByte(cur.add(3)) & 0xff;
                int strlen1 = lenLo | (lenHi << 8);
                String strValue1 = "str_len_%d".formatted(strlen1);
                stack.push(new StackItem("string", strValue1, enumLabel));
                return cur.add(4 + strlen1);
            case "HB_P_PUSHLOCALNEARINC": {
                int symbolId = mem.getByte(cur.add(1)) & 0xff;
                println("  ++%d".formatted(symbolId));
                return cur.add(dt.getLength());
            }
            case "HB_P_PUSHNIL":
                stack.push(new StackItem("nil", "nil", enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_PUSHSTATIC":
                int staticRef = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("static", "var_%d".formatted(staticRef), enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_PUSHSTRSHORT":
                int strlen = mem.getByte(cur.add(1)) & 0xff;
                String strValue = "str_len_%d".formatted(strlen);
                stack.push(new StackItem("string", strValue, enumLabel));
                return cur.add(2 + strlen);
            case "HB_P_PUSHSYMNEAR":
                int symbolId = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("static", "pSymbol[%d]".formatted(symbolId), enumLabel));
                return cur.add(2);
            case "HB_P_RETVALUE":
                if (!stack.isEmpty()) {
                    StackItem top = stack.pop();
                    println("  RETURN %s".formatted(top));
                } else {
                    println("  RETURN <empty>");
                }
                return cur.add(dt.getLength());
            case "HB_P_SFRAME":
                int function = mem.getByte(cur.add(1)) & 0xff;
                println("FUNCTION pSymbol[%d]()".formatted(function - 1));
                stack.push(new StackItem("frame", "sframe", enumLabel));
                return cur.add(dt.getLength());
            default:
                printerr("Unknown opcode: %s".formatted(enumLabel));
                stack.push(new StackItem("unknown", "0x%02X".formatted(opcode), enumLabel));
                return cur.add(dt.getLength());
        }
    }

    private Address findNextLabelAfter(Address start) {
        SymbolTable st = currentProgram.getSymbolTable();
        Address begin = start.add(1L);
        if (begin == null) {
            return null;
        }

        SymbolIterator it = st.getSymbolIterator(begin, true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Symbol s = it.next();
            if (s == null) {
                continue;
            }
            if (s.getSymbolType() == SymbolType.LABEL) {
                Address a = s.getAddress();
                if (a != null && a.compareTo(start) > 0) {
                    return a;
                }
            }
        }
        return null;
    }

    private DataType resolveDataTypeByName(String typeName) {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        ArrayList<DataType> matches = new ArrayList<>();
        dtm.findDataTypes(typeName, matches);

        for (DataType candidate : matches) {
            if (candidate != null && typeName.equals(candidate.getName())) {
                return candidate;
            }
        }
        return null;
    }

    private Map<Integer, String> initializeHbPcodeCache() {
        Map<Integer, String> hbPcodeCache = new HashMap<>();
        if (currentProgram == null) {
            return hbPcodeCache;
        }
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        ArrayList<DataType> matches = new ArrayList<>();
        dtm.findDataTypes("HB_PCODE", matches);

        for (DataType dt : matches) {
            if (dt instanceof Enum en) {
                for (String n : en.getNames()) {
                    hbPcodeCache.put((int) en.getValue(n), n);
                }
            }
        }
        return hbPcodeCache;
    }

}
