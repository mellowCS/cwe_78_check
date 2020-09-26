package internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class Build {
	
	
	public static List<String> jmps = new ArrayList<String>() {{
		add("CALL");
		add("CALLIND");
		add("BRANCHIND");
		add("BRANCH");
		add("CBRANCH");
		add("RETURN");
	}}; 
	
	
	public static List<String> sysCallSyms = new ArrayList<String>() {{
		add("system");
		add("execl");
	}};
	
	
	public static HashMap<Function, ArrayList<Address>> callerSysMap;
	
	
	public static BlockGraph buildBlockGraph(FunctionManager funcMan, SimpleBlockModel simpleBm, Listing listing, VarnodeContext context, TaskMonitor monitor) {
		/*
		 * Builds a simple block graph which simply contains a Vector of CodeBlocks with source and destination addresses, 
		 * a wrapper function, entry point and simplified pcode instructions
		 * 
		 * */
		BlockGraph blockGraph = new BlockGraph(new ArrayList<Block>());
		for(Function function : funcMan.getFunctionsNoStubs(true)) {
			AddressSetView addresses = function.getBody();
			try {
				CodeBlockIterator blockIter = simpleBm.getCodeBlocksContaining(addresses, monitor);
				while(blockIter.hasNext()) {
					Block block = buildBlock(blockIter.next(), function, context, listing, funcMan, monitor);
					blockGraph.addBlock(block);
				}
			} catch(CancelledException e) {
				System.out.println("Could not retrieve basic blocks containing addresses.\n");
			}
		}
		return blockGraph;
	}
	
	
	public static Block buildBlock(CodeBlock codeBlock, Function function, VarnodeContext context, Listing listing, FunctionManager funcMan, TaskMonitor monitor) {
		/*
		 * Builds one block for the graph
		 * 
		 * */
		Block block = new Block();
		block.setEntryPoint(codeBlock.getFirstStartAddress());
		block.setWrappingFunction(function);
		block.setOps(buildInstructions(codeBlock, context, listing));
		block.setAddresses(getAddressVector(codeBlock));
		block.setSources(getNeighbouringAddresses(codeBlock, true, monitor));
		block.setDestinations(getNeighbouringAddresses(codeBlock, false, monitor));
		
		return block;
	}
	
	
	public static ArrayList<Address> getAddressVector(CodeBlock codeBlock) {
		ArrayList<Address> addresses = new ArrayList<Address>();
		codeBlock.getAddresses(true).forEachRemaining(addresses::add);
		return addresses;
	}
	
	
	public static ArrayList<Address> getNeighbouringAddresses(CodeBlock codeBlock, Boolean source, TaskMonitor monitor) {
		/*
		 * Gets all source and destination addresses for a block which refer to other blocks
		 * 
		 * */
		ArrayList<Address> sourceAddresses = new ArrayList<Address>();
		try {
			CodeBlockReferenceIterator blockRefIter;
			if(source) {
				blockRefIter = codeBlock.getSources(monitor);
			} else {
				blockRefIter = codeBlock.getDestinations(monitor);
			}
			while(blockRefIter.hasNext()) {
				Address neighbourAddr;
				if(source) {
					neighbourAddr = blockRefIter.next().getSourceAddress();
				} else {
					neighbourAddr = blockRefIter.next().getDestinationAddress();
				}
				sourceAddresses.add(neighbourAddr);
			} 
		} catch(CancelledException e) {
			System.out.println("Could not build neighbouring blocks.\n");
		}
		
		return sourceAddresses;
	}
	
	
	public static ArrayList<InstructionCompound> buildInstructions(CodeBlock codeBlock, VarnodeContext context, Listing listing) {
		/*
		 * Builds simple instruction containing the mnemonic, generic in-/outputs and the address of the assembly instruction
		 * 
		 * */
		InstructionIterator instructions = listing.getInstructions(codeBlock, true);
		ArrayList<InstructionCompound> instrComs = new ArrayList<InstructionCompound>();
		while(instructions.hasNext()) {
			Instruction instruction = instructions.next();
			instrComs.add(buildInstructionCompound(instruction, context));	
		}
		
		return instrComs;
	}
	
	
	public static InstructionCompound buildInstructionCompound(Instruction instruction, VarnodeContext context) {
		InstructionCompound instrCompound = new InstructionCompound(new ArrayList<SimpleInstruction>());
		instrCompound.setInstruction(instruction);
		instrCompound.setResultObjects(new ArrayList<String>());
		instrCompound.setInputObjects(new ArrayList<String>());
		for(Object res : instruction.getResultObjects()) {instrCompound.addResultObjects(res.toString());}
		for(Object in : instruction.getInputObjects()) {instrCompound.addInputObjects(in.toString());}
		instrCompound.setInstrAddr(instruction.getAddress());
		for(PcodeOp pcodeOp : instruction.getPcode(true)) {
			SimpleInstruction simpleInstr = new SimpleInstruction();
			if(!pcodeOp.getMnemonic().equals("STORE") && !jmps.contains(pcodeOp.getMnemonic())) {
				simpleInstr.setOutput(pcodeOp.getOutput());
			}
			
			ArrayList<Varnode> inputs = new ArrayList<Varnode>();
			for(int i = 0; i < pcodeOp.getNumInputs(); i++) {
				inputs.add(pcodeOp.getInput(i));
			}
			
			simpleInstr.setOp(pcodeOp);
			simpleInstr.setMnemonic(pcodeOp.getMnemonic());
			simpleInstr.setInputs(inputs);
			simpleInstr.setAddress(instruction.getAddress());
			instrCompound.addToGroup(simpleInstr);
			
		}
		
		return instrCompound;
	}
	
	
	public static void createCallerSysMap(SymbolTable symTab, FunctionManager funcMan) {
		for(Symbol sym : symTab.getDefinedSymbols()) {
			if(sysCallSyms.contains(sym.getName()) && !sym.isExternal()) {
				for(Reference ref : sym.getReferences()) {
					Function sysFunc = funcMan.getFunctionAt(sym.getAddress());
					Function func = funcMan.getFunctionContaining(ref.getFromAddress());
					Address calledAddr = ref.getFromAddress();
					if(func != null && !sysCallSyms.contains(func.getName())) {
						if(callerSysMap.get(sysFunc) == null) {
							ArrayList<Address> addresses = new ArrayList<Address>();
							addresses.add(calledAddr);
							callerSysMap.put(sysFunc, addresses);
						} else {
							callerSysMap.get(sysFunc).add(calledAddr);
						}
					}
				}
			}
		}
	}
}
