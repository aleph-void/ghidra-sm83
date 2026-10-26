// Imports Game Boy symbol files as labels and, optionally, functions.
//
// Formats (detected per line, so a file may mix them):
//   BB:AAAA name          RGBDS (rgblink -n), WLA-DX (wlalink -S) and BGB/no$gmb .sym files:
//                         hexadecimal bank and CPU address; ';' starts a comment
//   DEF name 0xAAAA       SDCC/GBDK .noi files (lcc -Wl-j): linear CPU address, no bank
//
// Banked addresses (4000-7FFF, 8000-9FFF with VBK, A000-BFFF, D000-DFFF with SVBK) go to the
// overlay block of that bank when the loader made one (rom2, xram1, wram3, vram1 ...), and to the
// default space otherwise (unbanked ROMs, cartridge RAM bank 0 ...).
//
// Script argument (headless) or file chooser (GUI): the symbol file. A second argument "functions"
// also creates a function at every label that is not local (no '.' in the name) and sits on an
// instruction that is not already inside a function; the instruction is disassembled first when
// the address is executable code that analysis has not reached.
//@category Game Boy

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class GameBoySymbolImport extends GhidraScript {
	private static final Pattern SYM = Pattern.compile("^([0-9A-Fa-f]{1,4}):([0-9A-Fa-f]{4})\\s+(\\S+)");
	private static final Pattern NOI = Pattern.compile("^DEF\\s+(\\S+)\\s+0[xX]([0-9A-Fa-f]+)");

	private Address resolve(int bank, int offset, boolean banked) {
		AddressSpace def = currentProgram.getAddressFactory().getDefaultAddressSpace();
		String overlay = null;
		if (banked) {
			if (offset >= 0x4000 && offset < 0x8000 && bank > 0) {
				overlay = "rom" + bank;
			}
			else if (offset >= 0x8000 && offset < 0xa000 && bank > 0) {
				overlay = "vram" + bank;
			}
			else if (offset >= 0xa000 && offset < 0xc000) {
				overlay = "xram" + bank;
			}
			else if (offset >= 0xd000 && offset < 0xe000 && bank > 1) {
				overlay = "wram" + bank;
			}
		}
		if (overlay != null) {
			AddressSpace space = currentProgram.getAddressFactory().getAddressSpace(overlay);
			if (space != null) {
				return space.getAddress(offset);
			}
		}
		return def.getAddress(offset);
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File file = args.length > 0 ? new File(args[0]) : askFile("Game Boy symbol file", "Import");
		boolean functions = args.length > 1 && args[1].equals("functions");
		int labels = 0, funcs = 0, skipped = 0;
		AddressSet starts = new AddressSet();
		try (BufferedReader r = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				int semi = line.indexOf(';');
				if (semi >= 0) {
					line = line.substring(0, semi).trim();
				}
				Address a;
				String name;
				Matcher m = SYM.matcher(line);
				if (m.find()) {
					a = resolve(Integer.parseInt(m.group(1), 16), Integer.parseInt(m.group(2), 16),
						true);
					name = m.group(3);
				}
				else if ((m = NOI.matcher(line)).find()) {
					a = resolve(0, Integer.parseInt(m.group(2), 16), false);
					name = m.group(1);
				}
				else {
					continue;
				}
				// RGBDS writes "Global.local"; the Ghidra namespace separator is "::"
				String label = name.replaceAll("[^A-Za-z0-9_.$@#]", "_");
				if (currentProgram.getMemory().contains(a)) {
					try {
						createLabel(a, label, !label.contains("."), SourceType.IMPORTED);
						labels++;
						if (!label.contains(".")) {
							starts.add(a);
						}
					}
					catch (Exception e) {
						skipped++;
					}
				}
				else {
					skipped++;
				}
			}
		}
		if (functions) {
			for (Address a : starts.getAddresses(true)) {
				if (monitor.isCancelled()) {
					break;
				}
				var block = currentProgram.getMemory().getBlock(a);
				if (block == null || !block.isExecute() || !(block.isInitialized() || block.isMapped())) {
					continue;
				}
				if (getFunctionContaining(a) != null) {
					continue;
				}
				if (getInstructionAt(a) == null &&
					getDataAt(a) == null) {
					new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
				}
				if (getInstructionAt(a) != null) {
					Function f = createFunction(a, null);
					if (f != null) {
						funcs++;
					}
				}
			}
		}
		println(String.format("%s: %d labels, %d functions created, %d skipped (no memory there)",
			file.getName(), labels, funcs, skipped));
	}
}
