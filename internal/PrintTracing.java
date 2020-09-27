package internal;

import java.math.BigInteger;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.VarnodeContext;

public class PrintTracing {
	
	
	public static void printSymbols() {
		if(!Build.callerSysMap.isEmpty()) {
			for(Function func : Build.callerSysMap.keySet()) {
				for(Address caller : Build.callerSysMap.get(func)) {
					System.out.printf("[System Function]: %s at %s called from %s\n", func.getName(), func.getEntryPoint(), caller.toString());
				}
			}
		}
	}
	
	public static void printCall(VarnodeContext context, TrackStorage storage) {
		System.out.printf("[TRACKED]: Called function %s @ %s\n\n", storage.getFunc().getName(), storage.getCall().toString());
			for(String called : storage.getCalledFuncs()) {
				System.out.printf("|---[VULNERABLE FUNCTION CALL]: %s\n", called);
			}
			System.out.println();
			for(String origin : storage.getOriginFuncs()) {
				System.out.printf("|---[POSSIBLE ORIGIN FUNCTION]: %s()\n", origin);
			}
			for(Varnode node : storage.getNodes()) {
				if(node.isRegister()) {
					System.out.printf("|---[PARAMETER LOCATION]: %s\n", context.getRegister(node).getName());
				} else {
					System.out.printf("|---[PARAMETER LOCATION]: %s\n", node.getAddress().toString());
				}
			}
			for(MemPos pos : storage.getMemPos()) {
				String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
				long off = new BigInteger(offset, 16).longValue();
				System.out.printf("|---[MEMORY LOCATION]: %s + %s\n", context.getRegister(pos.getRegister()).getName(), off);
			}
			System.out.println();
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


	public static void printResults(ArrayList<TrackStorage> finalOut, VarnodeContext context) {
		for(TrackStorage storage : finalOut) {
			System.out.println("#########################################################################");
			printCall(context, storage);
			if(!HelperFunctions.trackerIsConstant(storage)) {
				System.out.println("\n[RESULT]: System call is possibly vulnerable. Manual checks recommended.\n");
			} else {
				System.out.println("\n[RESULT]: System call is possibly safe. Manual checks recommended.\n");
			}
		}
		System.out.println("#########################################################################");
	}
}
