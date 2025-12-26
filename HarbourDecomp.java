//Analyze the current position for Harbour P-code
//@author Christoph Brill <opensource@christophbrill.de>
//@category Analysis
//@keybinding X
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
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;

import java.util.ArrayList;

public class HarbourDecomp extends GhidraScript {

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

        Memory mem = currentProgram.getMemory();
        try {
            byte b = mem.getByte(addr);
            int unsigned = b & 0xff;

            String enumLabel = resolveHbPcodeLabel(unsigned);
            if (enumLabel != null) {
                println("Byte at %s: 0x%02X (%d) => HB_PCODE.%s".formatted(addr, unsigned, unsigned, enumLabel));

                boolean applied = switch (enumLabel) {
                    case "HB_P_PUSHSTRSHORT" -> applyPushStrShortAt(addr);
                    case "HB_P_LOCALNEARSETSTR" -> applyLocalNearSetStrAt(addr);
                    case "HB_P_PUSHBLOCK" -> applyPushBlockAt(addr);
                    default -> applyTypeAt(addr, enumLabel);
                };

                if (!applied) {
                    printerr("Could not apply data type '%s' at %s".formatted(enumLabel, addr));
                }
            } else {
                printerr("Byte at %s: 0x%02X (%d) => HB_PCODE.<unknown>".formatted(addr, unsigned, unsigned));
            }
        } catch (MemoryAccessException e) {
            printerr("Unable to read memory at %s: %s".formatted(addr, e.getMessage()));
        }
    }

    private String resolveHbPcodeLabel(int unsignedByte) {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        ArrayList<DataType> matches = new ArrayList<>();
        dtm.findDataTypes("HB_PCODE", matches);
        // This is not the most efficient way, but given the limited number of
        // HB_PCODE values, it's okayish
        for (DataType dt : matches) {
            if (dt instanceof Enum en) {
                for (String n : en.getNames()) {
                    if (en.getValue(n) == (long) unsignedByte) {
                        return n;
                    }
                }
            }
        }

        return null;
    }

    private boolean applyTypeAt(Address addr, String typeName) {
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        ArrayList<DataType> matches = new ArrayList<>();
        dtm.findDataTypes(typeName, matches);

        DataType dt = null;
        for (DataType candidate : matches) {
            if (candidate != null && typeName.equals(candidate.getName())) {
                dt = candidate;
                break;
            }
        }
        if (dt == null) {
            return false;
        }

        try {
            int len = dt.getLength();
            Listing listing = currentProgram.getListing();

            if (len <= 0) {
                listing.clearCodeUnits(addr, addr, false);
            } else {
                Address end = addr.add(len - 1L);
                listing.clearCodeUnits(addr, end, false);
            }

            listing.createData(addr, dt);
            return true;
        } catch (Exception e) {
            printerr("Failed to apply type '%s' at %s: %s".formatted(typeName, addr, e.getMessage()));
            return false;
        }
    }

    private boolean applyPushStrShortAt(Address addr) {
        if (!applyTypeAt(addr, "HB_P_PUSHSTRSHORT")) {
            return false;
        }

        try {
            Memory mem = currentProgram.getMemory();
            int strlen = mem.getByte(addr.add(1L)) & 0xff;
            if (strlen == 0) {
                return true;
            }

            Address strAddr = addr.add(2L);
            return applyFixedLengthAt(strlen, strAddr, CharDataType.dataType);
        } catch (MemoryAccessException e) {
            printerr("Failed to read HB_P_PUSHSTRSHORT length at %s: %s".formatted(addr.add(1L), e.getMessage()));
            return false;
        } catch (Exception e) {
            printerr("Failed to apply HB_P_PUSHSTRSHORT string data at %s: %s".formatted(addr, e.getMessage()));
            return false;
        }
    }

    private boolean applyLocalNearSetStrAt(Address addr) {
        if (!applyTypeAt(addr, "HB_P_LOCALNEARSETSTR")) {
            return false;
        }

        try {
            Memory mem = currentProgram.getMemory();
            int lenLo = mem.getByte(addr.add(2L)) & 0xff;
            int lenHi = mem.getByte(addr.add(3L)) & 0xff;
            int strlen = lenLo | (lenHi << 8);
            if (strlen == 0) {
                return true;
            }

            Address strAddr = addr.add(4L);
            return applyFixedLengthAt(strlen, strAddr, CharDataType.dataType);
        } catch (MemoryAccessException e) {
            printerr("Failed to read HB_P_LOCALNEARSETSTR length at %s: %s".formatted(addr.add(2L), e.getMessage()));
            return false;
        } catch (Exception e) {
            printerr("Failed to apply HB_P_LOCALNEARSETSTR string data at %s: %s".formatted(addr, e.getMessage()));
            return false;
        }
    }

    private boolean applyPushBlockAt(Address addr) {
        if (!applyTypeAt(addr, "HB_P_PUSHBLOCK")) {
            return false;
        }

        try {
            Memory mem = currentProgram.getMemory();
            int len = mem.getByte(addr.add(1L)) & 0xff;
            if (len <= 0) {
                return true;
            }

            Address dataAddr = addr.add(2L);
            return applyFixedLengthAt(len, dataAddr, ByteDataType.dataType);
        } catch (MemoryAccessException e) {
            printerr("Failed to read HB_P_PUSHBLOCK fields at %s: %s".formatted(addr, e.getMessage()));
            return false;
        } catch (Exception e) {
            printerr("Failed to apply HB_P_PUSHBLOCK data at %s: %s".formatted(addr, e.getMessage()));
            return false;
        }
    }

    private boolean applyFixedLengthAt(int len, Address dataAddr, DataType dt) throws CodeUnitInsertionException {
        Address dataEnd = dataAddr.add(len - 1L);

        Listing listing = currentProgram.getListing();
        listing.clearCodeUnits(dataAddr, dataEnd, false);

        DataType charArr = new ArrayDataType(dt, len, 1);
        listing.createData(dataAddr, charArr);
        return true;
    }

}
