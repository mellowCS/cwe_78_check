//
//@author Melvin Klimke
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;

import internal.*;

public class OsComInjection extends GhidraScript {
	
	private HashMap<String, Integer[]> vulnFunctions = new HashMap<String, Integer[]> () {{
		put("strcat", new Integer[] {0, 1});
		put("strncat", new Integer[] {0, 1});
		put("sprintf", new Integer[] {1});
		put("snprintf", new Integer[] {2});
	}};
	
	
	private List<String> inputFunctions = new ArrayList<String> () {{
		add("__isoc99_scanf");
	}};
	
	
	private List<String> checkCharFunctions = new ArrayList<String> () {{
		add("strchr");
		add("strrchr");
		add("regcomp");
		add("regexec");
	}};	
	
	private List<String> binOps = new ArrayList<String>() {{
		add("INT_EQUAL");
		add("INT_NOTEQUAL");
		add("INT_LESS");
		add("INT_SLESS");
		add("INT_LESSEQUAL");
		add("INT_SLESSEQUAL");
		add("INT_ADD");
		add("INT_SUB");
		add("INT_CARRY");
		add("INT_SCARRY");
		add("INT_SBORROW");
		add("INT_XOR");
		add("INT_AND");
		add("INT_OR");
		add("INT_LEFT");
		add("INT_RIGHT");
		add("INT_SRIGHT");
		add("INT_MULT");
		add("INT_DIV");
		add("INT_REM");
		add("INT_SDIV");
		add("INT_SREM");
	}}; 
	
	private List<String> casts = new ArrayList<String>() {{
		add("INT_NEGATE");
		add("INT_ZEXT");
		add("INT_SEXT");
		add("TRUNC");
		add("INT2FLOAT");
		add("CAST");
	}};
	
	ArrayList<String> stackOps = new ArrayList<String>() {{
		add("PUSH");
		add("POP");
	}};
	
	ArrayList<TrackStorage> mergable = new ArrayList<TrackStorage>();
	ArrayList<TrackStorage> finalOut = new ArrayList<TrackStorage>();
	ArrayList<Register> parameterRegister = new ArrayList<Register>();
	String cpuArch;
	Register stackPointer;
	Register framePointer;
	Register returnRegister;
	AddressFactory addrFactory;
	Program program;
	FunctionManager funcMan;
	VarnodeContext context;

	@Override
	protected void run() throws Exception {
		program = currentProgram;
		funcMan = program.getFunctionManager();
		SimpleBlockModel simpleBm = new SimpleBlockModel(program);
		SymbolTable symTab = program.getSymbolTable();
		Listing listing = program.getListing();
		context = new VarnodeContext(program, program.getProgramContext(), program.getProgramContext());
		Build.callerSysMap = new HashMap<Function, ArrayList<Address>>();
		
		
		cpuArch = HelperFunctions.getCPUArch(program);
		stackPointer = program.getCompilerSpec().getStackPointer();
		framePointer = HelperFunctions.getFramePointer(cpuArch, context);
		returnRegister = HelperFunctions.getReturnRegister(cpuArch, context);
		parameterRegister = HelperFunctions.getParameterRegister(cpuArch, context);
		addrFactory = program.getAddressFactory();

		BlockGraph graph = Build.buildBlockGraph(funcMan, simpleBm, listing, context, getMonitor());
		Build.createCallerSysMap(symTab, funcMan);
		finalOut = findSourceOfSystemCallInput(graph);
		PrintTracing.printCalls(context, finalOut);
	}

	
	/*
	 * -------------------------------------------------------------------------------------------------------
	 * Gets the input source for each system call
	 * -------------------------------------------------------------------------------------------------------
	 * */
	public ArrayList<TrackStorage> findSourceOfSystemCallInput(BlockGraph blockGraph) {
		ArrayList<TrackStorage> output = new ArrayList<TrackStorage>();
		for(Function sysFunc : Build.callerSysMap.keySet()) {
			/*
			 * -------------------------------------------------------------------------------------------------------
			 * 1. Get the function's parameters and map them to Varnodes, also get stack parameters if available and remove stack varnodes from parameters
			 * 2. Iterate over each address where the function is called
			 * -------------------------------------------------------------------------------------------------------
			 * */
			ArrayList<Varnode> params = HelperFunctions.getFunctionParameters(sysFunc, context);
			ArrayList<MemPos> stackArgs = HelperFunctions.getStackArgs(stackPointer, addrFactory, params, context);
			params = HelperFunctions.removeStackNodes(params);
			for(Address callAddr : Build.callerSysMap.get(sysFunc)) {
				//if(i == 0) {i++; continue;}
				/*
				 * -------------------------------------------------------------------------------------------------------
				 * 1. Create a TrackStorage for each system call
				 * 2. Get the first block where the system call was made
				 * 3. Track the output of the of the first block
				 * 4. Trace its sources recursively and merge outgoing track storages
				 * -------------------------------------------------------------------------------------------------------
				 * */
				TrackStorage storage = new TrackStorage(sysFunc, callAddr, params, stackArgs, new ArrayList<String>(), new ArrayList<String>());
				Block startBlock = blockGraph.getBlockByAddress(callAddr);
				buildTraceToProgramStart(storage, 0, blockGraph, startBlock);
				mergable.add(storage);
				output.add(mergeTrackerForSystemCall());
			}
		}
		
		return output;
	}
	
	
	/*
	 * -------------------------------------------------------------------------------------------------------
	 * Recursively iterate through source blocks and get the corresponding TrackStorage
	 * -------------------------------------------------------------------------------------------------------
	 * */
	public void buildTraceToProgramStart(TrackStorage storage, int depthLevel, BlockGraph graph, Block block) {
		/*
		 * -------------------------------------------------------------------------------------------------------
		 * 1. Iterate over all source blocks of the current block
		 * 2. For each source block, get the TrackStorage output
		 * 3. Recursively call getTrace for each source block and use their TracksStorages as input
		 * -------------------------------------------------------------------------------------------------------
		 * */
		Boolean noSrc = true;
		getInputLocationAtBlockStart(storage, block, depthLevel);
		if(!HelperFunctions.trackerIsConstant(storage)) {
			for(Address src : block.getSources()) {
				Block srcBlock = graph.getBlockByAddress(src);
				if(srcBlock != null && depthLevel < 15) {
					noSrc = false;
					buildTraceToProgramStart(storage, depthLevel+1, graph, srcBlock);
				}
			}
			if(noSrc) {
				return;
			}
		} 

		return;
	}
	
	
	/*
	 * -------------------------------------------------------------------------------------------------------
	 * Merge all track storages from the same recursion level
	 * -------------------------------------------------------------------------------------------------------
	 * */
	protected TrackStorage mergeTrackerForSystemCall() {
		TrackStorage merge = new TrackStorage(mergable.get(0).getFunc(), mergable.get(0).getCall(), new ArrayList<Varnode>(), new ArrayList<MemPos>(), new ArrayList<String>(), new ArrayList<String>());
		for(TrackStorage storage : mergable) {
			merge.getNodes().addAll(storage.getNodes());
			merge.getMemPos().addAll(storage.getMemPos());
			merge.getCalledFuncs().addAll(storage.getCalledFuncs());
			merge.getOriginFuncs().addAll(storage.getOriginFuncs());
		}
		ArrayList<Varnode> mergedNodes = new ArrayList<Varnode>(merge.getNodes().stream().distinct().collect(Collectors.toList()));
		ArrayList<MemPos> mergedMem = new ArrayList<MemPos>(merge.getMemPos().stream().distinct().collect(Collectors.toList()));
		ArrayList<String> mergedCalled = new ArrayList<String>(merge.getCalledFuncs().stream().distinct().collect(Collectors.toList()));
		ArrayList<String> mergedOrigin = new ArrayList<String>(merge.getOriginFuncs().stream().distinct().collect(Collectors.toList()));
		merge.setNodes(mergedNodes);
		merge.setMemPos(mergedMem);
		merge.setCalledFuncs(mergedCalled);
		merge.setOriginFuncs(mergedOrigin);
		mergable.clear();
		
		return merge;
	}
	
	
	/*
	 * -------------------------------------------------------------------------------------------------------
	 * Return the tracked registers and memory positions for the current block
	 * -------------------------------------------------------------------------------------------------------
	 * */
	protected void getInputLocationAtBlockStart(TrackStorage storage, Block block, int depthLevel) {
		/*
		 * -------------------------------------------------------------------------------------------------------
		 * 1. Iterate over all instruction compounds of the block
		 * 2. For each instruction compound, check whether we have a register output or store something in memory
		 * 3. OUTPUT: If there is a register output, check whether it is one of the tracked registers
		 * 4. NO OUTPUT: If there is none, check whether the memory location is one of the locations that are tracked
		 * -------------------------------------------------------------------------------------------------------
		 * */
		ArrayList<InstructionCompound> groups = block.getOps();
		//PrintTracing.printTrace(storage, context, depthLevel, groups, groups.size() - 1);
		for(int i = groups.size(); i-- > 0;) {
			InstructionCompound group = groups.get(i);
			int numOfInstr = group.getGroup().size();
            // Check if current assembly instruction is a NOP
			if(numOfInstr > 0) {
				if(i == groups.size()-1 && depthLevel == 0) {
					continue;
				}
				
				if(i == groups.size()-1 && depthLevel > 0) {
					// Checks if the last Pcode instruction of a block is actually a jump
					PcodeOp branch = group.getGroup().get(numOfInstr - 1).getOp();
					if(Build.jmps.contains(branch.getMnemonic())) {
						checkForOriginFunction(group, storage, block, depthLevel, branch);
					} else {
						checkForInterestingObjects(storage, group, block);
					}
				} else {
					checkForInterestingObjects(storage, group, block);
				}
				
				//PrintTracing.printTrace(storage, context, depthLevel, groups, i);
				
				if(HelperFunctions.trackerIsConstant(storage)) {
					return;
				}
			}
			
		}
	}


	protected void checkForInterestingObjects(TrackStorage storage, InstructionCompound group, Block block) {
		ArrayList<Varnode> output = HelperFunctions.matchTrackedNodesWithOutput(storage, group.getResultObjects(), context);
		ArrayList<MemPos> input = HelperFunctions.matchTrackedMemPosWithOutput(stackPointer, storage, group.getInputObjects(), context);
				
		if(!output.isEmpty() || !input.isEmpty()) {
			if(group.getResultObjects().isEmpty()) {
				analysePcodeCompound(storage, group, block, output, input, true);
			} else {
				analysePcodeCompound(storage, group, block, output, input, false);
			}
		}
	}
	
	
	protected void analysePcodeCompound(TrackStorage storage, InstructionCompound group, Block block, ArrayList<Varnode> output, ArrayList<MemPos> input, Boolean noOutput) {
		ArrayList<SimpleInstruction> ops = group.getGroup();
		if(stackOps.contains(group.getInstruction().getMnemonicString())) {
			ArrayList<String> reg = storage.getMemPos().stream().map(m -> context.getRegister(m.getRegister()).getName()).collect(Collectors.toCollection(ArrayList::new));
			if(reg.contains(stackPointer.getName())) {
				updateStackVariables(storage, group);
			}
		} else if(noOutput) {
			Varnode newTracked = null;
			HelperFunctions.removeTrackedMemoryPositions(storage, input);
			for(SimpleInstruction op : ops) {
				if(op.getOp().getOpcode() == PcodeOp.STORE && !HelperFunctions.getStoreInput(op.getOp()).isUnique()) {
					newTracked = HelperFunctions.getStoreInput(op.getOp());
					storage.addNode(newTracked);
				}
			}
			if(newTracked == null) {
				for(SimpleInstruction op : ops) {
					if(op.getOp().getOpcode() == PcodeOp.COPY) {
						newTracked = op.getOp().getInput(0);
						if(HelperFunctions.notATrackedNode(storage, newTracked)) {
							storage.addNode(newTracked);
						}
					}
				}
			}
			
		} else {
			StackFrame frame = funcMan.getFunctionContaining(group.getInstruction().getAddress()).getStackFrame();
			for(int j = ops.size(); j-- > 0;) {
				analysePcodeOperation(storage, ops.get(j).getOp(), frame);
			}
			
		}
	}
	
	
	protected void checkForOriginFunction(InstructionCompound compound, TrackStorage storage, Block block, int depthLevel, PcodeOp branch) {
		Varnode remove = null;
		if(PcodeOp.CALL == branch.getOpcode()) {
			Function calledFunc = funcMan.getFunctionAt(branch.getInput(0).getAddress());
			if(checkCharFunctions.contains(calledFunc.getName()) && depthLevel < 4) {
				Varnode first = context.getRegisterVarnode(parameterRegister.get(0));
				if(HelperFunctions.notATrackedNode(storage, first)) {
					storage.addNode(first);
				}
				storage.addCalledFunc(calledFunc.getName());
			}
			else if(inputFunctions.contains(calledFunc.getName()) && depthLevel < 5) {
				getInputFunctionParams(storage, calledFunc);
			}
			else if(vulnFunctions.containsKey(calledFunc.getName()) && depthLevel < 3) {
				getVulnFunctionParams(storage, calledFunc);
				
			} else if(calledFunc.isThunk() && calledFunc.getParameterCount() == 0 && !calledFunc.hasNoReturn()) {
				for(Varnode node : storage.getNodes()) {
					if(node.isRegister() && returnRegister.getName().equals(context.getRegister(node).getName())) {
						remove = node;
						storage.addOriginFunc(calledFunc.getName());
					}
				}
				
			}
			if(remove != null) {
				storage.getNodes().remove(remove);
			}
		}
	}
	
	
	protected void getInputFunctionParams(TrackStorage storage, Function calledFunc) {
		storage.addCalledFunc(calledFunc.getName());
		if(!cpuArch.equals("x86_32")) {
			Varnode first = context.getRegisterVarnode(parameterRegister.get(0));
			Varnode second = context.getRegisterVarnode(parameterRegister.get(1));
			if(HelperFunctions.notATrackedNode(storage, first)) {
				storage.addNode(first);
			}
			if(HelperFunctions.notATrackedNode(storage, second)) {
				storage.addNode(second);
			}
		}
	}
	
	
	protected void getVulnFunctionParams(TrackStorage storage, Function calledFunc) {
		storage.addCalledFunc(calledFunc.getName());
		ArrayList<Varnode> newNodes = new ArrayList<Varnode>();
		Variable[] vars = calledFunc.getParameters();
		for(Integer idx : vulnFunctions.get(calledFunc.getName())) {
			Varnode var = vars[idx].getFirstStorageVarnode();
			if(var.isFree() && !var.isRegister()) {
				MemPos pos = new MemPos(context.getRegisterVarnode(stackPointer), new Varnode(addrFactory.getConstantAddress(var.getAddress().getOffset()), var.getSize()));
				if(HelperFunctions.notATrackedMemoryPosition(storage, pos.getRegister(), pos.getOffset(), context)) {
					storage.addMem(pos);
				}
			} else {
				newNodes.add(var);
			}
		}
		for(Varnode node : storage.getNodes()) {
			if(node.isConstant()) {
				newNodes.add(node);
			}
		}
		if(cpuArch.equals("ARM-32")) {
			if(calledFunc.getName().equals("sprintf")) {
				newNodes.add(context.getRegisterVarnode(context.getRegister("r2")));
			} else if(calledFunc.getName().equals("snprintf")) {
				newNodes.add(context.getRegisterVarnode(context.getRegister("r3")));
			}
		}
		
		storage.setNodes(newNodes);
	}
	
	
	protected void updateStackVariables(TrackStorage storage, InstructionCompound group) {
		PcodeOp firstInstr = group.getGroup().get(0).getOp();
		if(PcodeOp.COPY == firstInstr.getOpcode()) {
			Varnode in = firstInstr.getInput(0);
			if(HelperFunctions.notATrackedNode(storage, in)) {
				storage.addNode(in);
			}
		} else if(PcodeOp.INT_ADD == firstInstr.getOpcode()) {
			MemPos newPos = new MemPos(firstInstr.getInput(0), firstInstr.getInput(1));
			if(HelperFunctions.notATrackedMemoryPosition(storage, newPos.getRegister(), newPos.getOffset(), context)) {
				storage.addMem(newPos);
			}
		}
		
		HelperFunctions.removeStackPointer(stackPointer, storage, context);
	}
	
	
	protected void analysePcodeOperation(TrackStorage storage, PcodeOp op, StackFrame frame) {
		
		Varnode output = op.getOutput();
		ArrayList<Long> varOffsets = HelperFunctions.getStackVarOffsets(frame);
		ArrayList<Varnode> trackedNodes = storage.getNodes();
		
		if(trackedNodes.contains(output)) {
			
			if(binOps.contains(op.getMnemonic())) {
				
				updateNodeAndMemoryTracker(storage, op, varOffsets, output);
				
			} else if (casts.contains(op.getMnemonic())) {
				
				trackedNodes.remove(output);
				
			} else if(op.getOpcode() == PcodeOp.COPY) {
				
				trackedNodes.remove(output);
				storage.addNode(op.getInput(0));
				
			} else if (op.getOpcode() == PcodeOp.LOAD) {
				
				trackedNodes.remove(output);
				if(op.getNumInputs() == 2) {
					storage.addNode(op.getInput(1));
				} else {
					storage.addNode(op.getInput(0));
				}
				
			}
		}
	}
	
	
	protected void updateNodeAndMemoryTracker(TrackStorage storage, PcodeOp op, ArrayList<Long> varOffsets, Varnode output) {
		if(PcodeOp.INT_ADD == op.getOpcode() || PcodeOp.INT_SUB == op.getOpcode()) {
			if(op.getInput(0).isRegister() && op.getInput(1).isConstant() && op.getInput(0).isRegister() && !op.getInput(0).toString().equals(output.toString())) {
				storage.getNodes().remove(output);
				if(HelperFunctions.notATrackedMemoryPosition(storage, op.getInput(0), op.getInput(1), context)) {
					storage.getMemPos().add(new MemPos(op.getInput(0), op.getInput(1)));
				}
			} else if(op.getInput(0).isRegister() && op.getInput(1).isRegister()) {
				storage.getNodes().remove(output);
				storage.getNodes().add(op.getInput(1));
			}
		}
	}
	
}
