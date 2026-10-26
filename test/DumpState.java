// Prints memory blocks, functions and flow references of an analysed program (debug helper).
//@category Testing
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
public class DumpState extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
			println("BLOCK " + b.getName() + " " + b.getStart() + "-" + b.getEnd() + " x=" + b.isExecute() + " init=" + b.isInitialized() + " ov=" + b.isOverlay());
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			println("FUNC " + f.getName() + " @ " + f.getEntryPoint() + " " + f.getBody());
		}
	}
}
