// P-code semantics check for the SM83 module (after Ghidra-Rare's VAXEmuTest). Reads
// test/emu/cases.txt; for each case writes the code at ram:1000, sets registers and memory,
// emulates with Ghidra's EmulatorHelper until the PC reaches the end of the main code
// (subroutines may follow it), and compares registers and memory with values worked out by hand
// from the Game Boy CPU manual (Pan Docs / Gekkio's Complete Technical Reference).
// SP starts at C100h, all other registers at 0.
//
// The CPU-control userops (IME, halt, stop, mbc_write, bank_ram) are given Java callbacks that
// record what the instruction asked for: expect ime <0|1>, halts <n>, stops <n>.
//
// Case file lines: case <name> / code <hex> / main <len> /
//   set <reg> <value> | set ram:<hexaddr>[/<n>] <value>   (n bytes, little-endian)
//   expect <reg> <value> | expect ram:<hexaddr>[/<n>] <value> | expect ime|halts|stops <n> / end
// Script args: <cases.txt> <outfile>
//@category Testing

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.pcode.Varnode;

public class SM83EmuTest extends GhidraScript {

	private static class Case {
		String name;
		byte[] code;
		int mainLen = -1;
		Map<String, Long> set = new LinkedHashMap<>();
		Map<String, Long> expect = new LinkedHashMap<>();
	}

	private long ime, halts, stops;

	private List<Case> load(String path) throws Exception {
		List<Case> cases = new ArrayList<>();
		Case c = null;
		try (BufferedReader r = new BufferedReader(new FileReader(path))) {
			String line;
			while ((line = r.readLine()) != null) {
				line = line.trim();
				if (line.isEmpty() || line.startsWith("#")) {
					continue;
				}
				String[] f = line.split("\\s+");
				switch (f[0]) {
					case "case":
						c = new Case();
						c.name = f[1];
						break;
					case "code":
						c.code = new byte[f[1].length() / 2];
						for (int i = 0; i < c.code.length; i++) {
							c.code[i] = (byte) Integer.parseInt(f[1].substring(2 * i, 2 * i + 2), 16);
						}
						break;
					case "main":
						c.mainLen = Integer.decode(f[1]);
						break;
					case "set":
						c.set.put(f[1], Long.decode(f[2]));
						break;
					case "expect":
						c.expect.put(f[1], Long.decode(f[2]));
						break;
					case "end":
						cases.add(c);
						break;
					default:
						throw new IllegalArgumentException("bad line: " + line);
				}
			}
		}
		return cases;
	}

	private Address addr(String loc) {
		String[] p = loc.split("[:/]");
		return currentProgram.getAddressFactory().getAddressSpace(p[0]).getAddress(
			Long.parseLong(p[1], 16));
	}

	private int size(String loc) {
		String[] p = loc.split("/");
		return p.length > 1 ? Integer.parseInt(p[1]) : 1;
	}

	private void callbacks(EmulatorHelper emu) {
		emu.registerCallOtherCallback("IME", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				ime = emulate.getMemoryState().getValue(op.getInput(1));
				return true;
			}
		});
		emu.registerCallOtherCallback("halt", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				halts++;
				return true;
			}
		});
		emu.registerCallOtherCallback("stop", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				stops++;
				return true;
			}
		});
		// identity, as the decompiler hint it is; a write to the MBC register area is stored
		emu.registerCallOtherCallback("bank_ram", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				Varnode out = op.getOutput();
				emulate.getMemoryState().setValue(out,
					emulate.getMemoryState().getValue(op.getInput(1)));
				return true;
			}
		});
		emu.registerCallOtherCallback("mbc_write", new BreakCallBack() {
			@Override
			public boolean pcodeCallback(PcodeOpRaw op) {
				long a = emulate.getMemoryState().getValue(op.getInput(1));
				long v = emulate.getMemoryState().getValue(op.getInput(2));
				emulate.getMemoryState().setValue(
					currentProgram.getAddressFactory().getDefaultAddressSpace(), a, 1, v);
				return true;
			}
		});
	}

	private String runCase(Case c) throws Exception {
		Address start = addr("ram:1000");
		int mainLen = c.mainLen >= 0 ? c.mainLen : c.code.length;
		Address end = start.add(mainLen);
		AddressSet body = new AddressSet(start, start.add(c.code.length + 16));
		clearListing(body);
		setBytes(start, c.code);
		ime = -1;
		halts = 0;
		stops = 0;
		final EmulatorHelper emu = new EmulatorHelper(currentProgram);
		try {
			callbacks(emu);
			emu.writeRegister("SP", 0xC100);
			for (Map.Entry<String, Long> e : c.set.entrySet()) {
				if (e.getKey().contains(":")) {
					int n = size(e.getKey());
					byte[] b = new byte[n];
					for (int i = 0; i < n; i++) {
						b[i] = (byte) (e.getValue() >> (8 * i));
					}
					emu.writeMemory(addr(e.getKey()), b);
				}
				else {
					emu.writeRegister(e.getKey(), e.getValue());
				}
			}
			emu.writeRegister(emu.getPCRegister(), start.getOffset());
			int steps = 0;
			while (!emu.getExecutionAddress().equals(end)) {
				if (++steps > 500) {
					return "did not reach the end (pc " + emu.getExecutionAddress() + ")";
				}
				if (!emu.step(monitor)) {
					return "emulation error at " + emu.getExecutionAddress() + ": " +
						emu.getLastError();
				}
			}
			StringBuilder bad = new StringBuilder();
			for (Map.Entry<String, Long> e : c.expect.entrySet()) {
				long got;
				String k = e.getKey();
				if (k.contains(":")) {
					int n = size(k);
					byte[] b = emu.readMemory(addr(k), n);
					got = 0;
					for (int i = n - 1; i >= 0; i--) {
						got = (got << 8) | (b[i] & 0xff);
					}
				}
				else if (k.equals("ime")) {
					got = ime;
				}
				else if (k.equals("halts")) {
					got = halts;
				}
				else if (k.equals("stops")) {
					got = stops;
				}
				else {
					got = emu.readRegister(k).longValue();
				}
				if (got != e.getValue()) {
					bad.append(String.format(" %s=0x%x (expected 0x%x)", k, got, e.getValue()));
				}
			}
			return bad.length() == 0 ? null : bad.toString().trim();
		}
		finally {
			emu.dispose();
		}
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		List<Case> cases = load(args[0]);
		PrintStream out = new PrintStream(args[1]);
		int pass = 0, fail = 0;
		for (Case c : cases) {
			String err = runCase(c);
			if (err == null) {
				pass++;
				out.println("PASS " + c.name);
			}
			else {
				fail++;
				out.println("FAIL " + c.name + ": " + err);
			}
		}
		out.printf("emulation (%s): %d passed, %d failed%n", currentProgram.getLanguageID(), pass,
			fail);
		out.close();
	}
}
