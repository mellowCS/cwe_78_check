package internal;

import java.math.BigInteger;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.VarnodeContext;

public class PrintTracing {
	
	public static void printBlock(int depthLevel, Block block, FunctionManager funcMan, VarnodeContext context, ArrayList<String> jmps) {
		System.out.printf("[BLOCK] @ %s in function %s ------------> Depthlevel = %s\n\n", block.getEntryPoint(), 
				block.getWrappingFunction().getName(), depthLevel);
		for(Address src : block.getSources()) {
			System.out.printf("|---[SOURCE]: %s\n", src.toString());
		} 
		System.out.printf("\n--------------------------------\n\n");
		for(Address dest : block.getDestinations()) {
			System.out.printf("|---[DEST]: %s\n", dest.toString());
		}
		System.out.printf("\n--------------------------------\n\n");
		for(InstructionCompound sC : block.getOps()) {
			for(SimpleInstruction sIn : sC.getGroup()) {
				if(sIn.getMnemonic().equals("STORE") || jmps.contains(sIn.getMnemonic())) {
					System.out.printf("|-------[OP]: <%s> ", sIn.getMnemonic());
				} else {
					if(sIn.getOutput().isRegister()) {
						System.out.printf("|-------[OP]: <%s> %s:%s = ", sIn.getMnemonic(), context.getRegister(sIn.getOutput()).getName(), sIn.getOutput().getSize());
					} else {
						System.out.printf("|-------[OP]: <%s> %s:%s = ", sIn.getMnemonic(), sIn.getOutput().getAddress().getOffset(), sIn.getOutput().getSize());
					}
				}
				for(Varnode var : sIn.getInputs()) {
					if(var.isRegister()) {
						System.out.printf("%s:%s, ", context.getRegister(var).getName(), var.getSize());
					} else {
						System.out.printf("%s:%s, ", var.getAddress().getOffset(), var.getSize());
					}
				}
				System.out.println();
			}
			System.out.println();
		}
		SimpleInstruction callInstr = block.getBranch();
		if(callInstr != null && callInstr.getMnemonic().equals("CALL")) {
			Function calledFunc = funcMan.getFunctionAt(callInstr.getInputs().get(0).getAddress());
			StackFrame frame = calledFunc.getStackFrame();
			Variable[] params = calledFunc.getParameters();
			int stackParams = frame.getParameterOffset();
			System.out.printf("\n--------------------------------\n\n");
			System.out.printf("Function called: %s\n", calledFunc.getName());
			if(params.length == 0) {
				if(stackParams == 0) {
					System.out.println("No parameters found!");
				} else {
					System.out.printf("|-------[PARAM OFFSET]: %s\n", stackParams);
				}
			}
			for(Variable var : params) {
				if(var.isStackVariable()) {
					System.out.printf("|-------[CALL VAR]: stack [%s]\n", var.getStackOffset());
				} else {
					System.out.printf("|-------[CALL VAR]: %s\n", var.getRegister().getName());
				}
				System.out.printf("|-------[DEFINED]: %s\n", var.getFirstStorageVarnode());
			}
		}
		System.out.println("\n####################################################################################################\n");
		
	}
	
	
	public static void printBlockGraph(BlockGraph graph, FunctionManager funcMan, VarnodeContext context, ArrayList<String> jmps) {
		for(Block block : graph.getGraph()) {
			printBlock(0, block, funcMan, context, jmps);
		}
	}
	
	
	public static void printSymbols() {
		if(!Build.callerSysMap.isEmpty()) {
			for(Function func : Build.callerSysMap.keySet()) {
				for(Address caller : Build.callerSysMap.get(func)) {
					System.out.printf("[System Function]: %s at %s called from %s\n", func.getName(), func.getEntryPoint(), caller.toString());
				}
			}
		}
	}
	
	public static void printCalls(VarnodeContext context, ArrayList<TrackStorage> finalOut) {
		for(TrackStorage storage : finalOut) {
			System.out.printf("[TRACK]: Called function %s @ %s\n\n", storage.getFunc().getName(), storage.getCall().toString());
			for(String called : storage.getCalledFuncs()) {
				System.out.printf("|---[OTHER]: %s\n", called);
			}
			System.out.println();
			for(String origin : storage.getOriginFuncs()) {
				System.out.printf("|---[ORIGIN]: %s()\n", origin);
			}
			for(Varnode node : storage.getNodes()) {
				if(node.isRegister()) {
					System.out.printf("|---[PARAM]: %s\n", context.getRegister(node).getName());
				} else {
					System.out.printf("|---[PARAM]: %s\n", node.getAddress().toString());
				}
			}
			for(MemPos pos : storage.getMemPos()) {
				String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
				long off = new BigInteger(offset, 16).longValue();
				System.out.printf("|---[MEM]: %s + %s\n", context.getRegister(pos.getRegister()).getName(), off);
			}
			System.out.println();
		}
	}
	
	public static void printTrace(TrackStorage storage, VarnodeContext context, int depthLevel, ArrayList<InstructionCompound> groups, int i) {
		System.out.printf("Depthlevel: %d, Compound: %d\n\n", depthLevel, groups.size() - (i + 1));
		for(Varnode node : storage.getNodes()) {
			if(node.isRegister()) {
				System.out.printf("Tracked Node: %s\n", context.getRegister(node).getName());
			} else {
				System.out.printf("Tracked Node: %s\n", node.toString());
			}
		}
		for(MemPos pos : storage.getMemPos()) {
			String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
			System.out.printf("Tracked MemPos: %s + %s\n", context.getRegister(pos.getRegister()).getName(), new BigInteger(offset, 16).longValue());
		}
		System.out.println();
	}
}
