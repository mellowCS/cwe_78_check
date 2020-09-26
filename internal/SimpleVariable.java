package internal;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.Varnode;

public class SimpleVariable {
	private Varnode node;
	private String name;
	private String type;
	private Address target;
	private Address address;
	private int size;
	
	public SimpleVariable() {}
	
	public SimpleVariable(String name, Address address, int size) {
		this.setName(name);
		this.setAddress(address);
		this.setSize(size);
	}
	
	public String getName() {
		return name;
	}
	
	public void setName(String name) {
		this.name = name;
	}

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public Address getTarget() {
		return target;
	}

	public void setTarget(Address target) {
		this.target = target;
	}

	public Varnode getNode() {
		return node;
	}

	public void setNode(Varnode node) {
		this.node = node;
	}
}
