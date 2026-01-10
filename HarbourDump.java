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

    private Map<Integer, String> hbPcodeCache;
    private boolean headerPrinted;
    private Address entryAddress;

    private static class IfContext {
        final Address end;

        IfContext(Address end) {
            this.end = end;
        }
    }

    private static class IntRef {
        int value;

        IntRef(int value) {
            this.value = value;
        }
    }

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

        String expr() {
            return value;
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
        entryAddress = addr;

        // Initialize HB_PCODE cache once per script run
        hbPcodeCache = initializeHbPcodeCache();
        headerPrinted = false;

        // Initialize stack simulation
        Stack<StackItem> stack = new Stack<>();

        Stack<IfContext> ifStack = new Stack<>();
        IntRef indentLevel = new IntRef(0);

        // Fallback: If we never find a HB_P_RETVAL or HB_P_ENDPROC, we stop at the next label
        Address nextLabelAddr = findNextLabelAfter(addr);

        Memory mem = currentProgram.getMemory();
        Address maxAddr = currentProgram.getMaxAddress();

        Address cur = addr;
        while (cur != null && cur.compareTo(maxAddr) <= 0) {
            while (!ifStack.isEmpty() && cur.equals(ifStack.peek().end)) {
                indentLevel.value = Math.max(0, indentLevel.value - 1);
                println(indent(indentLevel.value) + "ENDIF");
                ifStack.pop();
            }

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
            cur = processOpcode(cur, opcode, enumLabel, stack, mem, indentLevel, ifStack);

            if ("HB_P_ENDPROC".equals(enumLabel)) {
                println("Stopping at terminator opcode: %s".formatted(enumLabel));
                break;
            }

            if (cur == null) {
                println("Reached end of address space during processing");
                break;
            }
        }
    }

    private static String indent(int level) {
        if (level <= 0) {
            return "";
        }
        return "   ".repeat(level);
    }

    private Address processOpcode(Address cur, int opcode, String enumLabel, Stack<StackItem> stack, Memory mem, IntRef indentLevel, Stack<IfContext> ifStack) throws MemoryAccessException {
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
                if (!headerPrinted) {
                    int nParams = mem.getByte(cur.add(2)) & 0xff;
                    String functionName = resolveFunctionNameAt(entryAddress);
                    if (functionName.endsWith("_bytecode")) {
                        functionName = functionName.substring(0, functionName.length() - "_bytecode".length());
                    }
                    StringBuilder sig = new StringBuilder();
                    sig.append("FUNCTION ");
                    sig.append(functionName);
                    sig.append("( ");
                    for (int i = 1; i <= nParams; i++) {
                        if (i > 1) {
                            sig.append(", ");
                        }
                        sig.append("local_");
                        sig.append(i);
                    }
                    sig.append(" )");
                    println(sig.toString());
                    headerPrinted = true;
                    indentLevel.value = Math.max(indentLevel.value, 1);
                }
                stack.push(new StackItem("frame", "frame", "HB_P_FRAME"));
                return cur.add(dt.getLength());
            case "HB_P_FALSE":
                stack.push(new StackItem("bool", ".F.", enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_FUNCTIONSHORT":
                int argc = mem.getByte(cur.add(1)) & 0xff;
                ArrayList<StackItem> args = new ArrayList<>();
                for (int i = 0; i < argc; i++) {
                    args.add(0, stack.isEmpty() ? null : stack.pop());
                }
                StackItem self = stack.isEmpty() ? null : stack.pop();
                StackItem sym = stack.isEmpty() ? null : stack.pop();
                String callee = sym != null ? sym.expr() : "<unknown>";
                StringBuilder call = new StringBuilder();
                call.append(callee);
                call.append("( ");
                for (int i = 0; i < args.size(); i++) {
                    if (i > 0) {
                        call.append(",");
                    }
                    StackItem a = args.get(i);
                    call.append(a != null ? a.expr() : "<unknown>");
                }
                call.append(" )");

                String callExpr = call.toString();
                stack.push(new StackItem("call", callExpr, enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_LOCALNEARSETSTR":
                int lenLo = mem.getByte(cur.add(2)) & 0xff;
                int lenHi = mem.getByte(cur.add(3)) & 0xff;
                int strlen1 = lenLo | (lenHi << 8);
                String strValue1 = "str_len_%d".formatted(strlen1);
                stack.push(new StackItem("string", strValue1, enumLabel));
                return cur.add(4 + strlen1);
            case "HB_P_PUSHNIL":
                stack.push(new StackItem("nil", "NIL", enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_PUSHLOCALNEAR": {
                int localId = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("local", "local_%d".formatted(localId), enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_POPLOCALNEAR": {
                int localId = mem.getByte(cur.add(1)) & 0xff;
                StackItem rhs = stack.isEmpty() ? null : stack.pop();
                println(indent(indentLevel.value) + "local_%d := %s".formatted(localId, rhs != null ? rhs.expr() : "<empty>"));
                return cur.add(dt.getLength());
            }
            case "HB_P_LOCALNEARADD": {
                int localId = mem.getByte(cur.add(1)) & 0xff;
                StackItem rhs = stack.isEmpty() ? null : stack.pop();
                println(indent(indentLevel.value) + "local_%d += %s".formatted(localId, rhs != null ? rhs.expr() : "<empty>"));
                return cur.add(dt.getLength());
            }
            case "HB_P_PUSHSTATIC":
                int staticRef = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("static", "var_%d".formatted(staticRef), enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_PUSHBYTE": {
                int v = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("number", "%d".formatted(v), enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_ONE":
                stack.push(new StackItem("number", "1", enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_PUSHINT": {
                int lo = mem.getByte(cur.add(1)) & 0xff;
                int hi = mem.getByte(cur.add(2)) & 0xff;
                int imm = (short) (lo | (hi << 8));
                stack.push(new StackItem("number", "%d".formatted(imm), enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_PUSHSTRSHORT":
                int strlen = mem.getByte(cur.add(1)) & 0xff;
                String strValue = readStringLiteral(mem, cur.add(2), strlen);
                stack.push(new StackItem("string", strValue, enumLabel));
                return cur.add(2 + strlen);
            case "HB_P_NOTEQUAL": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s != %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> != <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_EQUAL": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s == %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> == <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_DUPLICATE": {
                if (!stack.isEmpty()) {
                    StackItem top = stack.peek();
                    stack.push(new StackItem(top.type, top.value, enumLabel));
                } else {
                    stack.push(new StackItem("unknown", "<empty>", enumLabel));
                }
                return cur.add(dt.getLength());
            }
            case "HB_P_PUSHSYMNEAR":
                int symbolId = mem.getByte(cur.add(1)) & 0xff;
                stack.push(new StackItem("symbol", "pSymbol[%d]".formatted(symbolId - 1), enumLabel));
                return cur.add(2);
            case "HB_P_POP":
                if (!stack.isEmpty()) {
                    StackItem v = stack.pop();
                    if (v != null && "call".equals(v.type)) {
                        println(indent(indentLevel.value) + v.expr());
                    }
                }
                return cur.add(dt.getLength());
            case "HB_P_ZERO":
                stack.push(new StackItem("number", "0", enumLabel));
                return cur.add(dt.getLength());
            case "HB_P_GREATER": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s > %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> > <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_GREATEREQUAL": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s >= %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> >= <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_EXACTLYEQUAL": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s == %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> == <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_AND": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s .AND. %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> .AND. <unknown>";
                }
                stack.push(new StackItem("bool", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_ARRAYPUSH": {
                StackItem index = stack.isEmpty() ? null : stack.pop();
                StackItem array = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (array != null && index != null) {
                    expr = "%s[%s]".formatted(array.expr(), index.expr());
                } else {
                    expr = "<unknown>[<unknown>]";
                }
                stack.push(new StackItem("arrayref", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_JUMPFALSENEAR": {
                int rel = mem.getByte(cur.add(1));
                StackItem cond = stack.isEmpty() ? null : stack.pop();
                println(indent(indentLevel.value) + "IF %s".formatted(cond != null ? cond.expr() : "<empty>"));
                Address end = cur.add(dt.getLength() + rel);
                ifStack.push(new IfContext(end));
                indentLevel.value++;
                return cur.add(dt.getLength());
            }
            case "HB_P_JUMPFALSE": {
                int lo = mem.getByte(cur.add(1)) & 0xff;
                int hi = mem.getByte(cur.add(2)) & 0xff;
                int rel = (short) (lo | (hi << 8));
                StackItem cond = stack.isEmpty() ? null : stack.pop();
                println(indent(indentLevel.value) + "IF %s".formatted(cond != null ? cond.expr() : "<empty>"));
                Address end = cur.add(dt.getLength() + rel);
                ifStack.push(new IfContext(end));
                indentLevel.value++;
                return cur.add(dt.getLength());
            }
            case "HB_P_JUMPTRUENEAR": {
                int rel = mem.getByte(cur.add(1));
                StackItem cond = stack.isEmpty() ? null : stack.pop();
                Address dest = cur.add(dt.getLength() + rel);
                println(indent(indentLevel.value) + "JUMPIFTRUE %s -> %s".formatted(cond != null ? cond.expr() : "<empty>", dest));
                return cur.add(dt.getLength());
            }
            case "HB_P_JUMPNEAR": {
                int rel = mem.getByte(cur.add(1));
                Address dest = cur.add(dt.getLength() + rel);
                println(indent(indentLevel.value) + "JUMP -> %s".formatted(dest));
                if (rel > 0) {
                    return dest;
                }
                return cur.add(dt.getLength());
            }
            case "HB_P_LOCALNEARSETINT": {
                int localId = mem.getByte(cur.add(1)) & 0xff;
                int immBytes = Math.max(0, dt.getLength() - 2);
                long imm = 0;
                for (int i = 0; i < immBytes; i++) {
                    imm |= (long) (mem.getByte(cur.add(2L + i)) & 0xff) << (8 * i);
                }
                if (immBytes == 1) {
                    imm = (byte) imm;
                } else if (immBytes == 2) {
                    imm = (short) imm;
                } else if (immBytes == 4) {
                    imm = (int) imm;
                }
                println(indent(indentLevel.value) + "local_%d := %d".formatted(localId, imm));
                return cur.add(dt.getLength());
            }
            case "HB_P_ADDINT": {
                int lo = mem.getByte(cur.add(1)) & 0xff;
                int hi = mem.getByte(cur.add(2)) & 0xff;
                int imm = lo | (hi << 8);
                if ((imm & 0x8000) != 0) {
                    imm = imm - 0x10000;
                }
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null) {
                    expr = "%s + %d".formatted(left.expr(), imm);
                } else {
                    expr = "<unknown> + %d".formatted(imm);
                }
                stack.push(new StackItem("number", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_MULT": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s * %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> * <unknown>";
                }
                stack.push(new StackItem("number", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_DIVIDE": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s / %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> / <unknown>";
                }
                stack.push(new StackItem("number", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_MINUS": {
                StackItem right = stack.isEmpty() ? null : stack.pop();
                StackItem left = stack.isEmpty() ? null : stack.pop();
                String expr;
                if (left != null && right != null) {
                    expr = "%s - %s".formatted(left.expr(), right.expr());
                } else {
                    expr = "<unknown> - <unknown>";
                }
                stack.push(new StackItem("number", expr, enumLabel));
                return cur.add(dt.getLength());
            }
            case "HB_P_LOCALNEARINC": {
                int localId = mem.getByte(cur.add(1)) & 0xff;
                println(indent(indentLevel.value) + "++local_%d".formatted(localId));
                return cur.add(dt.getLength());
            }
            case "HB_P_LOCALNEARSE": {
                // Local initialization/assignment helper used by the compiler; keep parsing aligned.
                return cur.add(dt.getLength());
            }
            case "HB_P_PUSHBLOCK": {
                int len = mem.getByte(cur.add(1)) & 0xff;
                Address payloadStart = cur.add(2);
                println(indent(indentLevel.value) + "PUSHBLOCK {|...|} (len=%d)".formatted(len));
                String blockExpr = decodeBlock(payloadStart, len, mem, indent(indentLevel.value + 1));
                stack.push(new StackItem("block", blockExpr != null ? blockExpr : "{|...|}", enumLabel));
                return cur.add(2 + len);
            }
            case "HB_P_ENDBLOCK": {
                if (!stack.isEmpty()) {
                    StackItem top = stack.pop();
                    stack.push(new StackItem("block", "end(%s)".formatted(top), enumLabel));
                } else {
                    stack.push(new StackItem("block", "end(<empty>)", enumLabel));
                }
                return cur.add(dt.getLength());
            }
            case "HB_P_RETVALUE":
                if (!stack.isEmpty()) {
                    StackItem top = stack.pop();
                    println(indent(indentLevel.value) + "RETURN %s".formatted(top.expr()));
                } else {
                    println(indent(indentLevel.value) + "RETURN <empty>");
                }
                while (!ifStack.isEmpty()) {
                    indentLevel.value = Math.max(0, indentLevel.value - 1);
                    println(indent(indentLevel.value) + "ENDIF");
                    ifStack.pop();
                }
                return cur.add(dt.getLength());
            case "HB_P_SFRAME":
                int function = mem.getByte(cur.add(1)) & 0xff;
                println("FUNCTION pSymbol[%d]()".formatted(function - 1));
                headerPrinted = true;
                indentLevel.value = Math.max(indentLevel.value, 1);
                stack.push(new StackItem("frame", "sframe", enumLabel));
                return cur.add(dt.getLength());
            default:
                printerr("Unknown opcode: %s".formatted(enumLabel));
                stack.push(new StackItem("unknown", "0x%02X".formatted(opcode), enumLabel));
                return cur.add(dt.getLength());
        }
    }

    private String decodeBlock(Address start, int len, Memory mem, String indent) throws MemoryAccessException {
        if (hbPcodeCache == null) {
            return null;
        }

        Address cur = start;
        Address end = start.add(len);
        Stack<StackItem> stack = new Stack<>();
        String lastReturn = null;

        while (cur != null && cur.compareTo(end) < 0 && !monitor.isCancelled()) {
            int opcode = mem.getByte(cur) & 0xff;
            String enumLabel = hbPcodeCache.get(opcode);
            if (enumLabel == null) {
                println(indent + "<unknown opcode 0x%02X>".formatted(opcode));
                cur = cur.add(1);
                continue;
            }

            if ("HB_P_RETVALUE".equals(enumLabel)) {
                StackItem top = stack.isEmpty() ? null : stack.pop();
                lastReturn = top != null ? top.expr() : null;
                println(indent + "RETURN %s".formatted(lastReturn != null ? lastReturn : "<empty>"));
                DataType dataType = resolveDataTypeByName(enumLabel);
                cur = cur.add(dataType != null ? dataType.getLength() : 1);
                continue;
            }

            cur = processOpcode(cur, opcode, enumLabel, stack, mem, new IntRef(indent.length() / 2), new Stack<>());
        }

        return lastReturn;
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

    private String resolveFunctionNameAt(Address start) {
        if (currentProgram == null || start == null) {
            return "<unknown>";
        }
        SymbolTable st = currentProgram.getSymbolTable();
        Symbol s = st.getPrimarySymbol(start);
        if (s != null && s.getSymbolType() == SymbolType.LABEL && s.getName() != null && !s.getName().isBlank()) {
            return s.getName();
        }
        return "pcode_%s".formatted(start);
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

    private static String readStringLiteral(Memory mem, Address start, int len) throws MemoryAccessException {
        if (len <= 0) {
            return "\"\"";
        }

        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < len; i++) {
            int b = mem.getByte(start.add(i)) & 0xff;
            if (b == 0) {
                break;
            }
            if (b == '"' || b == '\\') {
                sb.append('\\');
                sb.append((char) b);
            } else if (b >= 0x20 && b < 0x7f) {
                sb.append((char) b);
            } else {
                sb.append(String.format("\\x%02X", b));
            }
        }
        sb.append('"');
        return sb.toString();
    }

}
