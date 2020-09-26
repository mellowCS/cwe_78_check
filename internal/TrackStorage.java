package internal;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;

public class TrackStorage {
	private Function func;
	private ArrayList<String> originFuncs;
	private ArrayList<String> calledFuncs;
	private Address call;
	private ArrayList<Varnode> nodes;
	private ArrayList<MemPos> memPos;
	
	public TrackStorage() {}
	
	public TrackStorage(Function func, Address call, ArrayList<Varnode> registers, ArrayList<MemPos> memPos, ArrayList<String> calledFuncs, ArrayList<String> originFuncs) {
		this.setFunc(func);
		this.setCall(call);
		this.setNodes(registers);
		this.setMemPos(memPos);
		this.setCalledFuncs(calledFuncs);
		this.setOriginFuncs(originFuncs);
	}
	
	public ArrayList<Varnode> getNodes() {
		return nodes;
	}
	
	public void setNodes(ArrayList<Varnode> registers) {
		this.nodes = registers;
	}

	public ArrayList<MemPos> getMemPos() {
		return memPos;
	}

	public void setMemPos(ArrayList<MemPos> memPos) {
		this.memPos = memPos;
	}

	public Address getCall() {
		return call;
	}

	public void setCall(Address call) {
		this.call = call;
	}

	public Function getFunc() {
		return func;
	}

	public void setFunc(Function func) {
		this.func = func;
	}
	
	public void addNode(Varnode node) {
		this.nodes.add(node);
	}
	
	public void addMem(MemPos mem) {
		this.memPos.add(mem);
	}

	public ArrayList<String> getCalledFuncs() {
		return calledFuncs;
	}

	public void setCalledFuncs(ArrayList<String> calledFuncs) {
		this.calledFuncs = calledFuncs;
	}
	
	public void addCalledFunc(String calledFunc) {
		calledFuncs.add(calledFunc);
	}

	public ArrayList<String> getOriginFuncs() {
		return originFuncs;
	}

	public void setOriginFuncs(ArrayList<String> originFuncs) {
		this.originFuncs = originFuncs;
	}
	
	public void addOriginFunc(String originFunc) {
		originFuncs.add(originFunc);
	}
}
