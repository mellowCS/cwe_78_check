package internal;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class Block {
	private Address entryPoint;
	private Function wrappingFunction;
	private ArrayList<InstructionCompound> ops;
	private ArrayList<Address> addresses;
	private ArrayList<Address> destinations;
	private ArrayList<Address> sources;
	
	public Address getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(Address entryPoint) {
		this.entryPoint = entryPoint;
	}
	
	public Function getWrappingFunction() {
		return wrappingFunction;
	}

	public void setWrappingFunction(Function wrappingFunction) {
		this.wrappingFunction = wrappingFunction;
	}
	
	public ArrayList<InstructionCompound> getOps() {
		return ops;
	}

	public void setOps(ArrayList<InstructionCompound> ops) {
		this.ops = ops;
	}
	
	public ArrayList<Address> getAddresses() {
		return addresses;
	}
	
	public void setAddresses(ArrayList<Address> addresses) {
		this.addresses = addresses;
	}

	public ArrayList<Address> getDestinations() {
		return destinations;
	}

	public void setDestinations(ArrayList<Address> destinations) {
		this.destinations = destinations;
	}

	public ArrayList<Address> getSources() {
		return sources;
	}

	public void setSources(ArrayList<Address> sources) {
		this.sources = sources;
	}
	
	public SimpleInstruction getBranch() {
		ArrayList<SimpleInstruction> in = ops.get(ops.size()-1).getGroup();
		if(in != null && !in.isEmpty()) {
			return in.get(in.size()-1);
		}
		
		return null;
	}

}
