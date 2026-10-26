// Decompiles the functions named in the script args (after importing a symbol file) and prints their C.
// Script args: <symbols file> <convention> <function name>...
//@category Testing
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
public class DecompAt extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		runScript("GameBoySymbolImport.java", new String[] { args[0], "functions" });
		DecompInterface di = new DecompInterface();
		di.openProgram(currentProgram);
		for (int i = 2; i < args.length; i++) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals(args[i])) {
					f.setCallingConvention(args[1]);
					var r = di.decompileFunction(f, 30, monitor);
					println("C>>> " + (r.decompileCompleted() ? r.getDecompiledFunction().getC() : "FAILED"));
				}
			}
		}
	}
}
