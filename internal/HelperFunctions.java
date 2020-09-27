package internal;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.VarnodeContext;

public class HelperFunctions {
	public static Register getReturnRegister(String cpuArch, VarnodeContext context) {
		switch(cpuArch) {
		case "x86-64": return context.getRegister("RAX");
		case "x86-32": return context.getRegister("EAX");
		case "ARM-32": return context.getRegister("r0");
		default: return context.getRegister("v0");
		}
	}
	
	
	public static Register getFramePointer(String cpuArch, VarnodeContext context) {
		switch(cpuArch) {
		case "x86-64": return context.getRegister("RBP");
		case "x86-32": return context.getRegister("EBP");
		case "ARM-32": return context.getRegister("r11");
		default: return context.getRegister("fp");
		}
	}
	
	
	public static ArrayList<Register> getParameterRegister(String cpuArch, VarnodeContext context) {
		ArrayList<Register> parameters = new ArrayList<Register>();
		switch(cpuArch) {
		case "x86-64": {
			parameters.add(context.getRegister("RDI"));
			parameters.add(context.getRegister("RSI"));
			parameters.add(context.getRegister("RDX"));
			parameters.add(context.getRegister("RCX"));
			parameters.add(context.getRegister("R8"));
			parameters.add(context.getRegister("R9"));
			return parameters;
		}
		case "x86-32": return parameters;
		case "ARM-32": {
			parameters.add(context.getRegister("r0"));
			parameters.add(context.getRegister("r1"));
			parameters.add(context.getRegister("r2"));
			parameters.add(context.getRegister("r3"));
			return parameters;
		}
		default: {
			parameters.add(context.getRegister("a0"));
			parameters.add(context.getRegister("a1"));
			parameters.add(context.getRegister("a2"));
			parameters.add(context.getRegister("a3"));
			return parameters;
		}
		}
	}
	
	
	public static String getCPUArch(Program program) {
		String langId = program.getCompilerSpec().getLanguage().getLanguageID().getIdAsString();
		String[] arch = langId.split(":");
		System.out.println(arch[0] + "-" + arch[2]);
		return arch[0] + "-" + arch[2];
	}
	
	
	public static ArrayList<MemPos> getStackArgs(Register stackPointer, AddressFactory addrFactory, ArrayList<Varnode> params, VarnodeContext context) {
		ArrayList<MemPos> stackArgs = new ArrayList<MemPos>();
		for(Varnode param : params) {
			if(param.isFree() && !param.isRegister()) {
				stackArgs.add(new MemPos(context.getRegisterVarnode(stackPointer), new Varnode(addrFactory.getConstantAddress(param.getAddress().getOffset()), param.getSize())));
			}
		}
		
		return stackArgs;
	}
	
	
	public static ArrayList<Varnode> removeStackNodes(ArrayList<Varnode> params) {
		ArrayList<Varnode> clean = new ArrayList<Varnode>();
		for(Varnode param : params) {
			if(param.isRegister()) {
				clean.add(param);
			}
		}
		
		return clean;
	}
	
	
	/*
	 * -------------------------------------------------------------------------------------------------------
	 * Checks whether all inputs have been tracked to a constant. If so, it returns true which serves as a break condition for a path
	 * -------------------------------------------------------------------------------------------------------
	 * */
	public static Boolean trackerIsConstant(TrackStorage storage) {
		if(storage.getMemPos().isEmpty()) {
			for(Varnode node : storage.getNodes()) {
				if(!node.isConstant()) {
					return false;
				}
			}
			return true;
		}
		return false;
	}
	
	
	public static Boolean isNegative(String input) {
		if(input.startsWith("-")) {
			return true;
		}
		return false;
	}
	
	
	public static String getReferencedData(Program program, Instruction instr) {
		Reference[] memRef = instr.getReferencesFrom();
		for(Reference ref : memRef) {
			if(ref.isMemoryReference()) {
				Data data = DataUtilities.getDataAtAddress(program, ref.getToAddress());
				return data.getDefaultValueRepresentation();
			}
		}
		
		return null;
	}
	
	
	public static ArrayList<Varnode> getFunctionParameters(Function func, VarnodeContext context) {
		Parameter[] params = func.getParameters();
		ArrayList<Varnode> inputs = new ArrayList<Varnode>();
		for(Parameter param : params) {
			inputs.add(param.getFirstStorageVarnode());
		}
		
		return inputs;
	}
	
	
	public static ArrayList<Long> getStackVarOffsets(StackFrame frame) {
		ArrayList<Long> varOffsets = new ArrayList<Long>();
		for(Variable var : frame.getStackVariables()) {
			varOffsets.add((long)var.getStackOffset());
		}
		
		return varOffsets;
	}
	
	
	public static void removeStackPointer(Register stackPointer, TrackStorage storage, VarnodeContext context) {
		ArrayList<MemPos> updated = new ArrayList<MemPos>();
		Boolean removed = false;
		for(MemPos pos : storage.getMemPos()) {
			if(removed) {
				updated.add(pos);
			} else if(!context.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
				updated.add(pos);
			} else {
				removed = true;
			}
		}
		storage.setMemPos(updated);
	}
	
	
	public static void removeTrackedMemoryPositions(TrackStorage storage, ArrayList<MemPos> input) {
		for(MemPos pos : input) {
			storage.getMemPos().remove(pos);
		}
	}
	
	
	public static Boolean checkIfStoreInputisVirtual(PcodeOp op) {
		if(op.getNumInputs() == 3) {
			return op.getInput(2).isUnique();
		}
		return op.getInput(1).isUnique();
	}


	public static Varnode parseStoreInput(PcodeOp op) {
		if(op.getNumInputs() == 3) {
			return op.getInput(2);
		}
		return op.getInput(1);
	}
	
	
	public static ArrayList<Varnode> matchTrackedNodesWithOutput(TrackStorage storage, ArrayList<String> output, VarnodeContext context){
		ArrayList<Varnode> seen = new ArrayList<Varnode>();
		for(String out : output) {
			for(Varnode node : storage.getNodes()) {
				if(node.isRegister() && context.getRegister(node).getName().equals(out)) {
					seen.add(node);
				}
			}
		}
		
		return seen;
	}
	
	
	public static ArrayList<MemPos> matchTrackedMemPosWithInput(Register stackPointer, TrackStorage storage, ArrayList<String> inputs, VarnodeContext context) {
		ArrayList<MemPos> tracked = new ArrayList<MemPos>();
		MemPos stackPos = stackPointerTracked(stackPointer, storage, context);
		if(inputs.contains(stackPointer.getName()) && stackPos != null) {
			tracked.add(stackPos);
		} else {
			tracked = matchOffset(storage, tracked, inputs, context);
		}
		
		return tracked;
	}
	
	
	public static ArrayList<MemPos> matchOffset(TrackStorage storage, ArrayList<MemPos> tracked, ArrayList<String> inputs, VarnodeContext context) {
		for(String in : inputs) {
			if(in.startsWith("0x") || in.startsWith("-0x")) {
				for(MemPos pos : storage.getMemPos()) {
					String offset = pos.getOffset().getAddress().toString().replaceFirst("^const:", "");
					try {
						long input = 0;
						if(HelperFunctions.isNegative(in)) {
							input = new BigInteger(in.replaceFirst("^-0x", ""), 16).longValue();
							input *= -1;
						} else {
							input = new BigInteger(in.replaceFirst("^0x", ""), 16).longValue();
						}
						long off = new BigInteger(offset, 16).longValue();
						if((input == off || (input *= -1) == off) && inputs.contains(context.getRegister(pos.getRegister()).getName())) {
							tracked.add(pos);
						}
					} catch(NumberFormatException e) {
						continue;
					}
				}
			}
		}
		
		return tracked;
	}
	
	
	public static MemPos stackPointerTracked(Register stackPointer, TrackStorage storage, VarnodeContext context) {
		for(MemPos pos : storage.getMemPos()) {
			if(context.getRegister(pos.getRegister()).getName().equals(stackPointer.getName())) {
				return pos;
			}
		}
		return null;
	}


	public static void getFunctionParams(TrackStorage storage, Function calledFunc, VarnodeContext context, ArrayList<Register> parameterRegister, String cpuArch, AddressFactory addrFactory, Register stackPointer, int arg_count) {
		storage.addCalledFunc(calledFunc.getName());
		if(!cpuArch.equals("x86-32")) {
			for(int c = 0; c < arg_count; c++) {
				Varnode arg = context.getRegisterVarnode(parameterRegister.get(c));
				if(storage.notATrackedNode(arg)) {
					storage.addNode(arg);
				}
			}
		} else {
			for(int c = 0; c < arg_count; c++) {
				storage.addMem(new MemPos(context.getRegisterVarnode(stackPointer), new Varnode(addrFactory.getConstantAddress((c + 1) * 4), 4)));
			}
		}
	}
	
	
	public static void getVulnFunctionParams(TrackStorage storage, Function calledFunc, VarnodeContext context, ArrayList<Register> parameterRegister, HashMap<String, Integer> vulnFunctions, String cpuArch, AddressFactory addrFactory, Register stackPointer) {
		storage.addCalledFunc(calledFunc.getName());
		if(!cpuArch.equals("x86-32")) {
			Varnode arg = context.getRegisterVarnode(parameterRegister.get(vulnFunctions.get(calledFunc.getName())));
			if(storage.notATrackedNode(arg)) {
				storage.addNode(arg);
			}
		} else {
			storage.addMem(new MemPos(context.getRegisterVarnode(stackPointer), new Varnode(addrFactory.getConstantAddress(4), 4)));
			storage.addMem(new MemPos(context.getRegisterVarnode(stackPointer), new Varnode(addrFactory.getConstantAddress(8), 4)));
		}
	}
	
	
	public static void updateStackVariables(TrackStorage storage, InstructionCompound group, VarnodeContext context, Register stackPointer) {
		PcodeOp firstInstr = group.getGroup().get(0).getOp();
		if(PcodeOp.COPY == firstInstr.getOpcode()) {
			Varnode in = firstInstr.getInput(0);
			if(storage.notATrackedNode(in)) {
				storage.addNode(in);
			}
		} else if(PcodeOp.INT_ADD == firstInstr.getOpcode()) {
			MemPos newPos = new MemPos(firstInstr.getInput(0), firstInstr.getInput(1));
			if(storage.notATrackedMemoryPosition(newPos.getRegister(), newPos.getOffset(), context)) {
				storage.addMem(newPos);
			}
		}
		
		removeStackPointer(stackPointer, storage, context);
	}
}
