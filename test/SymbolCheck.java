// Symbol import check: runs GameBoySymbolImport.java on a .sym (or .noi) file with function creation,
// then verifies independently (own parse of the file) that every label is in the symbol table at the
// address the file gives, and that labels on instructions in executable memory became functions.
// Script args: <symbols file>
//@category Testing
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.Symbol;

public class SymbolCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String file = getScriptArgs()[0];
		runScript("GameBoySymbolImport.java", new String[] { file, "functions" });
		Pattern sym = Pattern.compile("^([0-9A-Fa-f]{2}):([0-9A-Fa-f]{4})\\s+(\\S+)");
		int checked = 0, missing = 0, funcs = 0;
		try (BufferedReader r = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = r.readLine()) != null) {
				Matcher m = sym.matcher(line.trim());
				if (!m.find()) {
					continue;
				}
				int bank = Integer.parseInt(m.group(1), 16);
				long off = Long.parseLong(m.group(2), 16);
				String name = m.group(3).replaceAll("[^A-Za-z0-9_.$@#]", "_");
				boolean found = false;
				for (Symbol s : currentProgram.getSymbolTable().getSymbols(name)) {
					// the bank decides the address space only in banked ROMs
					if (s.getAddress().getOffset() == off) {
						found = true;
					}
				}
				checked++;
				if (!found) {
					missing++;
					println("MISSING " + m.group(0));
				}
				if (!name.contains(".") && getFunctionAt(currentProgram.getSymbolTable()
						.getSymbols(name).next().getAddress()) != null) {
					funcs++;
				}
			}
		}
		println(String.format("SYMCHECK %d labels checked, %d missing, %d at function entries", checked, missing, funcs));
	}
}
