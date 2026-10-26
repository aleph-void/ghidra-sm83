// Calling-convention check: imports a GBDK .noi symbol file, sets the given convention on every
// function whose name starts with an underscore (SDCC's C symbols) and prints the decompiler's
// signature of each.  Script args: <symbols.noi> <convention>
//@category Testing
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class ConvCheck extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		runScript("GameBoySymbolImport.java", new String[] { args[0], "functions" });
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.getName().startsWith("_")) {
				continue;
			}
			f.setCallingConvention(args[1]);
			var r = di.decompileFunction(f, 30, monitor);
			String c = r.decompileCompleted() ? r.getDecompiledFunction().getSignature() : "FAILED";
			println("SIG " + f.getName() + ": " + c);
		}
	}
}
