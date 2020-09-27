package internal;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.VarnodeContext;

public class TrackStorage {
	private Function func;
	private ArrayList<String> originFuncs;
	private ArrayList<String> calledFuncs;
	private Address call;
	private ArrayList<Varnode> nodes;
	private ArrayList<MemPos> memPos;
	
	public TrackStorage() {}
	
	public TrackStorage(Function func, Address call, ArrayList<Varnode> nodes, ArrayList<MemPos> memPos) {
		this.setFunc(func);
		this.setCall(call);
		this.setNodes(nodes);
		this.setMemPos(memPos);
		this.setCalledFuncs(new ArrayList<String>());
		this.setOriginFuncs(new ArrayList<String>());
	}
	
	public ArrayList<Varnode> getNodes() {
		return nodes;
	}
	
	public void setNodes(ArrayList<Varnode> registers) {
		this.nodes = registers;
	}

	public void addNode(Varnode node) {
		this.nodes.add(node);
	}

	public void removeNode(Varnode node) {
		this.nodes.remove(node);
	}

	public ArrayList<MemPos> getMemPos() {
		return memPos;
	}

	public void setMemPos(ArrayList<MemPos> memPos) {
		this.memPos = memPos;
	}

	public void addMem(MemPos mem) {
		this.memPos.add(mem);
	}

	public void removeMem(Varnode register, Varnode offset, VarnodeContext context) {
		for(MemPos pos : getMemPos()) {
			if(context.getRegister(pos.getRegister()).getName().equals(context.getRegister(register).getName()) && pos.getOffset().toString().equals(offset.toString())) {
				this.memPos.remove(pos);
			}
		}
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

	public Boolean notATrackedNode(Varnode node) {
		for(Varnode nd : getNodes()) {
			if(nd.toString().equals(node.toString())) {
				return false;
			}
		}
		return true;
	}
	
	
	public Boolean notATrackedMemoryPosition(Varnode register, Varnode offset, VarnodeContext context) {
		for(MemPos pos : getMemPos()) {
			if(context.getRegister(pos.getRegister()).getName().equals(context.getRegister(register).getName()) && pos.getOffset().toString().equals(offset.toString())) {
				return false;
			}
		}
		return true;
	}
}
