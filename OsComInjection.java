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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;

import internal.*;

public class OsComInjection extends GhidraScript {
	
	// Functions that may imply vulnerable input to the system calls
	private HashMap<String, Integer> vulnFunctions = new HashMap<String, Integer> () {{
		put("strcat", 1);
		put("strncat", 1);
		put("sprintf", 2);
		put("snprintf", 3);
		put("memcpy", 1);
	}};
	

	private List<String> inputFunctions = new ArrayList<String> () {{
		add("scanf");
		add("__isoc99_scanf");
	}};
	
	// Functions that check for characters and may imply a safe system call
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
		PrintTracing.printResults(finalOut, context);
	}

	
	
	
	/** 
	 * @param blockGraph
	 * @return ArrayList<TrackStorage>
	 * 
	 * Iterates over each system call and address at which it the function was called.
	 * In each iteration, a trace to the origin is generated and the tracked values are returned.
	 * 
	 */
	protected ArrayList<TrackStorage> findSourceOfSystemCallInput(BlockGraph blockGraph) {
		ArrayList<TrackStorage> output = new ArrayList<TrackStorage>();
		for(Function sysFunc : Build.callerSysMap.keySet()) {
			for(Address callAddr : Build.callerSysMap.get(sysFunc)) {
				ArrayList<Varnode> params = HelperFunctions.getFunctionParameters(sysFunc, context);
				ArrayList<MemPos> stackArgs = HelperFunctions.getStackArgs(stackPointer, addrFactory, params, context);
				// params contains stack arguments as Stack Varnodes which are removed in favour of using stackpointer + offset notation
			    params = HelperFunctions.removeStackNodes(params);
				TrackStorage storage = new TrackStorage(sysFunc, callAddr, params, stackArgs);
				Block startBlock = blockGraph.getBlockByAddress(callAddr);
				buildTraceToProgramStart(storage, 0, blockGraph, startBlock);
				output.add(mergeTrackerForSystemCall());
			}
		}
		
		return output;
	}
	
	
	
	
	/** 
	 * @param storage
	 * @param depthLevel
	 * @param graph
	 * @param block
	 * 
	 * Basic blocks, starting from the system call block, are recursively iterated backwards to find the origin
	 * If the tracked values are all constant, the iteration is stopped.
	 * For multiple tracked paths, the tracked values are put in an array of trackers for latter merging.
	 * 
	 */
	protected void buildTraceToProgramStart(TrackStorage storage, int depthLevel, BlockGraph graph, Block block) {
		getInputLocationAtBlockStart(storage, block, depthLevel);
		if(!HelperFunctions.trackerIsConstant(storage) && depthLevel < 15) {
			ArrayList<Block> sourceBlocks = filterSourcesByNull(graph, block.getSources());
			if(sourceBlocks.size() > 0) {
				buildTraceToProgramStart(storage, depthLevel+1, graph, sourceBlocks.get(0));
			    if(sourceBlocks.size() > 1) {
				    for(int index = 1; index < sourceBlocks.size(); index++) {
					    TrackStorage clone = deepCopy(storage);
					    buildTraceToProgramStart(clone, depthLevel+1, graph, sourceBlocks.get(index));
				    }
			    }
			} else {
				mergable.add(storage);
			}
		} else {
			mergable.add(storage);
		}
	}


	
	/** 
	 * @param graph
	 * @param sources
	 * @return ArrayList<Block>
	 * 
	 * Filters source blocks by checking if they are null
	 * 
	 */
	public ArrayList<Block> filterSourcesByNull(BlockGraph graph, ArrayList<Address> sources) {
		ArrayList<Block> filtered = new ArrayList<Block>();
		for(Address src : sources) {
			Block srcBlock = graph.getBlockByAddress(src);
			if(srcBlock != null) {
				filtered.add(srcBlock);
			}
		}

		return filtered;
	}


	
	/** 
	 * @param storage
	 * @return TrackStorage
	 * 
	 * Creates a deep copy of the tracker storage for following multiple paths that split from one
	 * 
	 */
	public TrackStorage deepCopy(TrackStorage storage) {
		TrackStorage clone = new TrackStorage(storage.getFunc(), storage.getCall(), new ArrayList<Varnode>(), new ArrayList<MemPos>());
		storage.getOriginFuncs().forEach(of -> clone.addOriginFunc(new String(of)));
		storage.getCalledFuncs().forEach(cf -> clone.addCalledFunc(new String(cf)));
		storage.getNodes().forEach(node -> clone.addNode(node));
		storage.getMemPos().forEach(pos -> clone.addMem(new MemPos(pos.getRegister(), pos.getOffset())));
		return clone;
	}
	
	
	
	
	/** 
	 * @return TrackStorage
	 * 
	 * If multiple trackers have been created, the results are merged into on tracker
	 * by simply checking for duplicates
	 * 
	 */
	protected TrackStorage mergeTrackerForSystemCall() {
		TrackStorage merge = new TrackStorage(mergable.get(0).getFunc(), mergable.get(0).getCall(), new ArrayList<Varnode>(), new ArrayList<MemPos>());
		for(TrackStorage storage : mergable) {
			merge.getNodes().addAll(storage.getNodes());
			merge.getMemPos().addAll(storage.getMemPos());
			merge.getCalledFuncs().addAll(storage.getCalledFuncs());
			merge.getOriginFuncs().addAll(storage.getOriginFuncs());
		}
		ArrayList<Varnode> mergedNodes = new ArrayList<Varnode>(merge.getNodes().stream().distinct().collect(Collectors.toList()));
		ArrayList<MemPos> mergedMem = mergeMemPos(merge);
		ArrayList<String> mergedCalled = new ArrayList<String>(merge.getCalledFuncs().stream().distinct().collect(Collectors.toList()));
		ArrayList<String> mergedOrigin = new ArrayList<String>(merge.getOriginFuncs().stream().distinct().collect(Collectors.toList()));
		merge.setNodes(mergedNodes);
		merge.setMemPos(mergedMem);
		merge.setCalledFuncs(mergedCalled);
		merge.setOriginFuncs(mergedOrigin);
		mergable.clear();
		
		return merge;
	}


	
	/** 
	 * @param merge
	 * @return ArrayList<MemPos>
	 * 
	 * Merges memory positions and removes duplicates
	 * 
	 */
	protected ArrayList<MemPos> mergeMemPos(TrackStorage merge){
		ArrayList<MemPos> filtered = new ArrayList<MemPos>();
		for(MemPos pos : merge.getMemPos()) {
			if(filtered.size() == 0) {
				filtered.add(pos);
			}
			for(MemPos fp : filtered) {
				if(!(fp.getRegister().toString().equals(pos.getRegister().toString()) && fp.getOffset().toString().equals(pos.getOffset().toString()))) {
					filtered.add(pos);
				}
			}
		}
		return filtered;
	}
	
	
	
	
	/** 
	 * @param storage
	 * @param block
	 * @param depthLevel
	 * 
	 * Iterates backwards over a basic block to get the system call input location at the start
	 * of the block.
	 * It ignores the very first assembly instruction as it belongs to the system call itself
	 * and checks each last intruction of a block for interesting function calls
	 * 
	 */
	protected void getInputLocationAtBlockStart(TrackStorage storage, Block block, int depthLevel) {
		ArrayList<InstructionCompound> groups = block.getOps();
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
				if(HelperFunctions.trackerIsConstant(storage)) {
					break;
				}
			}
			
		}
	}


	
	/** 
	 * @param storage
	 * @param group
	 * @param block
	 * 
	 * Checks whether assembly instructions contains in - or output objects that match an object in the tracker
	 * 
	 */
	protected void checkForInterestingObjects(TrackStorage storage, InstructionCompound group, Block block) {
		ArrayList<Varnode> matchedOutput = HelperFunctions.matchTrackedNodesWithOutput(storage, group.getResultObjects(), context);
		ArrayList<MemPos> matchedInput = HelperFunctions.matchTrackedMemPosWithInput(stackPointer, storage, group.getInputObjects(), context);
				
		if(!matchedOutput.isEmpty() || !matchedInput.isEmpty()) {
			if(group.getResultObjects().isEmpty()) {
				analysePcodeCompound(storage, group, block, matchedOutput, matchedInput, true);
			} else {
				analysePcodeCompound(storage, group, block, matchedOutput, matchedInput, false);
			}
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param group
	 * @param block
	 * @param output
	 * @param input
	 * @param noOutput
	 * 
	 * Analyses a group of Pcode instructions that belong to one assembly instruction.
	 * It further checks for stackpointer operations in the block.
	 * It treats the block differently, depending on it having output or not.
	 * If there ís no output, the STORE instruction is analysed, the whole block otherwise.
	 * 
	 */
	protected void analysePcodeCompound(TrackStorage storage, InstructionCompound group, Block block, ArrayList<Varnode> output, ArrayList<MemPos> input, Boolean noOutput) {
		ArrayList<SimpleInstruction> ops = group.getGroup();
		if(stackOps.contains(group.getInstruction().getMnemonicString())) {
			ArrayList<String> reg = storage.getMemPos().stream().map(m -> context.getRegister(m.getRegister()).getName()).collect(Collectors.toCollection(ArrayList::new));
			if(reg.contains(stackPointer.getName())) {
				HelperFunctions.updateStackVariables(storage, group, context, stackPointer);
			}
		}
		if(noOutput) {
			getStoredInput(storage, input, ops);
			
		} else {
			StackFrame frame = funcMan.getFunctionContaining(group.getInstruction().getAddress()).getStackFrame();
			for(int j = ops.size(); j-- > 0;) {
				analysePcodeOperation(storage, ops.get(j).getOp(), frame);
			}
			
		}
	}


	
	/** 
	 * @param storage
	 * @param input
	 * @param ops
	 * 
	 * Checks if the input of the store instruction comes from the COPY or STORE op.
	 * 
	 */
	protected void getStoredInput(TrackStorage storage, ArrayList<MemPos> input, ArrayList<SimpleInstruction> ops) {
		ArrayList<Varnode> copied = new ArrayList<Varnode>();
		HelperFunctions.removeTrackedMemoryPositions(storage, input);
		Boolean inputSet = false;
		for(SimpleInstruction op : ops) {
			if(op.getOp().getOpcode() == PcodeOp.COPY && !op.getOp().getInput(0).isUnique()) {
				copied.add(op.getOp().getInput(0));
			}
			if(op.getOp().getOpcode() == PcodeOp.STORE && !HelperFunctions.checkIfStoreInputisVirtual(op.getOp())) {
				inputSet = true;
				storage.addNode(HelperFunctions.parseStoreInput(op.getOp()));
			}
		}

		if(!inputSet) {
			for(Varnode cpy : copied) {
				storage.addNode(cpy);
			}
		}

	}
	
	
	
	/** 
	 * @param compound
	 * @param storage
	 * @param block
	 * @param depthLevel
	 * @param branch
	 * 
	 * Checks whether the called function is one of the vulnerable, input, checkchar or origin functions.
	 * In case a match was found, the tracker's register values and memory positions are removed and the input
	 * arguments of the matched function are inserted. (not in case of the origin function)
	 * 
	 */
	protected void checkForOriginFunction(InstructionCompound compound, TrackStorage storage, Block block, int depthLevel, PcodeOp branch) {
		if(PcodeOp.CALL == branch.getOpcode()) {
			Function calledFunc = funcMan.getFunctionAt(branch.getInput(0).getAddress());
			if(checkCharFunctions.contains(calledFunc.getName()) && depthLevel < 4) {
				int arg_count = 1;
				HelperFunctions.getFunctionParams(storage, calledFunc, context, parameterRegister, cpuArch, addrFactory, stackPointer, arg_count);
			}
			else if(inputFunctions.contains(calledFunc.getName()) && depthLevel < 5) {
				HelperFunctions.removeTracked(storage);
				int arg_count = 2;
				HelperFunctions.getFunctionParams(storage, calledFunc, context, parameterRegister, cpuArch, addrFactory, stackPointer, arg_count);
			}
			else if(vulnFunctions.containsKey(calledFunc.getName()) && depthLevel < 3) {
				HelperFunctions.removeTracked(storage);
				HelperFunctions.getVulnFunctionParams(storage, calledFunc, context, parameterRegister, vulnFunctions, cpuArch, addrFactory, stackPointer);
				
			} else if(calledFunc.isThunk() && calledFunc.getParameterCount() == 0 && !calledFunc.hasNoReturn()) {
				for(Varnode node : storage.getNodes()) {
					if(node.isRegister() && returnRegister.getName().equals(context.getRegister(node).getName())) {
						storage.addOriginFunc(calledFunc.getName());
						HelperFunctions.removeTracked(storage);
						break;
					}
				}
			}
		}
	}
	
	
	/** 
	 * @param storage
	 * @param op
	 * @param frame
	 * 
	 * Analyses a single Pcode instruction, depending on it being a Cast, BinOp, Copy or Load
	 * 
	 */
	protected void analysePcodeOperation(TrackStorage storage, PcodeOp op, StackFrame frame) {
		
		Varnode output = op.getOutput();
		ArrayList<Long> varOffsets = HelperFunctions.getStackVarOffsets(frame);
		ArrayList<Varnode> trackedNodes = storage.getNodes();
		
		if(trackedNodes.contains(output)) {
			if(binOps.contains(op.getMnemonic())) {
				updateNodeAndMemoryTracker(storage, op, varOffsets, output);	
			}
			if (casts.contains(op.getMnemonic())) {
				return;
			}
			if(op.getOpcode() == PcodeOp.COPY) {
				trackedNodes.remove(output);
				storage.addNode(op.getInput(0));
			}
			if (op.getOpcode() == PcodeOp.LOAD) {
				trackedNodes.remove(output);
				if(op.getNumInputs() == 2) {
					storage.addNode(op.getInput(1));
				} else {
					storage.addNode(op.getInput(0));
				}
			}
		}
	}
	
	
	
	/** 
	 * @param storage
	 * @param op
	 * @param varOffsets
	 * @param matchedOutput
	 * 
	 * Checks whether the Pcode instruction is either an INT_ADD or INT_SUB and if so, checks
	 * if the input is a memory position
	 * 
	 */
	protected void updateNodeAndMemoryTracker(TrackStorage storage, PcodeOp op, ArrayList<Long> varOffsets, Varnode matchedOutput) {
		if(PcodeOp.INT_ADD == op.getOpcode() || PcodeOp.INT_SUB == op.getOpcode()) {
			Varnode destination = op.getInput(0);
			Varnode source = op.getInput(1);
			if(destination.isRegister()) {
				if(source.isConstant()) {
					handleConstantSource(storage, destination, source, matchedOutput);
				} else {
					storage.removeNode(matchedOutput);
					storage.addNode(source);
				}
			}
		}
	}


	
	/** 
	 * @param storage
	 * @param destination
	 * @param source
	 * @param matchedOutput
	 * 
	 * Adds memory location to tracker if not yet available
	 * 
	 */
	protected void handleConstantSource(TrackStorage storage, Varnode destination, Varnode source, Varnode matchedOutput) {
		if(!destination.toString().equals(matchedOutput.toString())) {
			storage.removeNode(matchedOutput);
			if(storage.notATrackedMemoryPosition(destination, source, context)) {
				storage.addMem(new MemPos(destination, source));
			}
		}
	}
	
}
