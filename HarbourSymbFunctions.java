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
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
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
        long bytecodeLabelCreated = 0;
        long bytecodeLabelRenamed = 0;

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
                bytecodeLabelCreated += delta[3];
                bytecodeLabelRenamed += delta[4];
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
                    bytecodeLabelCreated += delta[3];
                    bytecodeLabelRenamed += delta[4];
                }
            }
        }

        println("HB_SYMB elements seen (typed): %d".formatted(symbElementsSeen));
        println("HB_SYMB elements used (valid szName+value): %d".formatted(symbElementsUsed));
        println("Created functions: %d".formatted(created));
        println("Renamed functions: %d".formatted(renamed));
        println("Created bytecode labels: %d".formatted(bytecodeLabelCreated));
        println("Renamed bytecode labels: %d".formatted(bytecodeLabelRenamed));
    }

    private long[] processSymbElement(Memory mem, Data symb) {

        Address szNamePtr = readStructPointerField(symb, "szName");
        Address valuePtr = readStructPointerField(symb, "value");
        if (szNamePtr == null || valuePtr == null) {
            return new long[]{0, 0, 0, 0, 0};
        }

        String name = readCString(mem, szNamePtr, MAX_NAME_LEN);
        if (name == null) {
            return new long[]{0, 0, 0, 0, 0};
        }

        String cleaned = stripQuotes(name);
        if (cleaned == null || cleaned.isBlank()) {
            return new long[]{0, 0, 0, 0, 0};
        }

        MemoryBlock valueBlock = mem.getBlock(valuePtr);
        if (valueBlock == null || !valueBlock.isExecute()) {
            return new long[]{0, 0, 0, 0, 0};
        }

        // returns {used, created, renamed, bytecodeLabelCreated, bytecodeLabelRenamed}
        long used = 1;
        long created = 0;
        long renamed = 0;
        long bytecodeLabelCreated = 0;
        long bytecodeLabelRenamed = 0;

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
                return new long[]{used, created, renamed, bytecodeLabelCreated, bytecodeLabelRenamed};
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

            // If the first call is hb_vmExecute(arg0,...), ensure arg0 has a label <FunctionName>_bytecode
            try {
                long[] bytecodeChanges = ensureHbVmExecuteBytecodeLabel(f);
                bytecodeLabelCreated += bytecodeChanges[0];
                bytecodeLabelRenamed += bytecodeChanges[1];
            } catch (Exception e) {
                printerr("Failed to apply hb_vmExecute bytecode label rule for %s: %s".formatted(f.getEntryPoint(), e.getMessage()));
            }
        }

        return new long[]{used, created, renamed, bytecodeLabelCreated, bytecodeLabelRenamed};
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

    private long[] ensureHbVmExecuteBytecodeLabel(Function f) throws Exception {
        if (f == null) {
            return new long[]{0, 0};
        }

        Instruction firstCall = findFirstCallInstruction(f);
        if (firstCall == null) {
            return new long[]{0, 0};
        }

        Address callTarget = resolveCallTarget(firstCall);
        if (callTarget == null) {
            return new long[]{0, 0};
        }
        if (!isHbVmExecute(callTarget)) {
            return new long[]{0, 0};
        }

        // Harbour hb_vmExecute is typically stdcall/cdecl-like with stack args.
        // The first parameter (pCode) is the last PUSH before the CALL.
        Address bytecodeAddr = resolveLastPushedAddress(firstCall, 32);
        if (bytecodeAddr == null) {
            return new long[]{0, 0};
        }

        String desired = f.getName() + "_bytecode";
        return ensureLabel(bytecodeAddr, desired);
    }

    private Instruction findFirstCallInstruction(Function f) {
        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(f.getBody(), true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Instruction ins = it.next();
            if (ins == null) {
                continue;
            }
            if (ins.getFlowType() != null && ins.getFlowType().isCall()) {
                return ins;
            }
        }
        return null;
    }

    private Address resolveCallTarget(Instruction callIns) {
        if (callIns == null) {
            return null;
        }
        Address[] flows = callIns.getFlows();
        if (flows != null && flows.length == 1 && flows[0] != null) {
            return flows[0];
        }
        return null;
    }

    private boolean isHbVmExecute(Address target) {
        if (target == null) {
            return false;
        }
        Function callee = getFunctionAt(target);
        if (callee != null) {
            return "hb_vmExecute".equals(callee.getName());
        }
        Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(target);
        return s != null && "hb_vmExecute".equals(s.getName());
    }

    private Address resolveLastPushedAddress(Instruction callIns, int maxBack) {
        Instruction cur = callIns != null ? callIns.getPrevious() : null;
        int steps = 0;
        while (cur != null && steps++ < maxBack && !monitor.isCancelled()) {
            String mnem = cur.getMnemonicString();
            if (mnem != null && mnem.equalsIgnoreCase("PUSH")) {
                Address direct = resolvePushOperandToAddress(cur);
                if (direct != null) {
                    return direct;
                }
            }
            cur = cur.getPrevious();
        }
        return null;
    }

    private Address resolvePushOperandToAddress(Instruction pushIns) {
        if (pushIns == null) {
            return null;
        }
        Object[] objs = pushIns.getOpObjects(0);
        if (objs == null) {
            return null;
        }

        for (Object o : objs) {
            if (o instanceof Address a) {
                return a;
            }
            if (o instanceof Scalar s) {
                long v = s.getUnsignedValue();
                if (v != 0) {
                    return toAddr(v);
                }
            }
            if (o instanceof Register r) {
                return resolveRegisterAsAddress(pushIns.getPrevious(), r, 32);
            }
        }
        return null;
    }

    private Address resolveRegisterAsAddress(Instruction start, Register reg, int maxBack) {
        Instruction cur = start;
        int steps = 0;
        while (cur != null && steps++ < maxBack && !monitor.isCancelled()) {
            String mnem = cur.getMnemonicString();
            if (mnem == null) {
                cur = cur.getPrevious();
                continue;
            }

            // Look for: MOV reg, imm/addr  OR  LEA reg, [addr]
            if (mnem.equalsIgnoreCase("MOV") || mnem.equalsIgnoreCase("LEA")) {
                Object[] dst = cur.getOpObjects(0);
                if (dst != null) {
                    boolean writesReg = false;
                    for (Object d : dst) {
                        if (d instanceof Register dr && dr.equals(reg)) {
                            writesReg = true;
                            break;
                        }
                    }
                    if (writesReg) {
                        Object[] src = cur.getOpObjects(1);
                        if (src != null) {
                            for (Object s : src) {
                                if (s instanceof Address a) {
                                    return a;
                                }
                                if (s instanceof Scalar sc) {
                                    long v = sc.getUnsignedValue();
                                    if (v != 0) {
                                        return toAddr(v);
                                    }
                                }
                            }
                        }
                        return null;
                    }
                }
            }

            cur = cur.getPrevious();
        }
        return null;
    }

    private long[] ensureLabel(Address addr, String desiredName) throws Exception {
        if (addr == null || desiredName == null || desiredName.isBlank()) {
            return new long[]{0, 0};
        }

        int created = 0;
        int renamed = 0;

        SymbolTable st = currentProgram.getSymbolTable();
        Symbol s = st.getPrimarySymbol(addr);
        if (s == null) {
            createLabel(addr, desiredName, true);
            println("Created label at %s (%s)".formatted(addr, desiredName));
            created++;
        }
        if (!desiredName.equals(s.getName())) {
            String old = s.getName();
            s.setName(desiredName, SourceType.USER_DEFINED);
            println("Renamed label at %s from %s to %s".formatted(addr, old, desiredName));
            renamed++;
        }
        return new long[]{created, renamed};

    }
}
