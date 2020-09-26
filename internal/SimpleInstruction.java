package internal;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class SimpleInstruction {
	private String mnemonic;
	private PcodeOp op;
	private Address address;
	private Varnode output;
	private ArrayList<Varnode> inputs;
	
	public SimpleInstruction() {}
	
	public SimpleInstruction(String mnemonic, Varnode output, ArrayList<Varnode> inputs) {
		this.setMnemonic(mnemonic);
		this.setOutput(output);
		this.setInputs(inputs);
	}
	
	public SimpleInstruction(String mnemonic, ArrayList<Varnode> inputs) {
		this.setMnemonic(mnemonic);
		this.setInputs(inputs);
	}
	
	public String getMnemonic() {
		return mnemonic;
	}
	
	public void setMnemonic(String mnemonic) {
		this.mnemonic = mnemonic;
	}

	public Varnode getOutput() {
		return output;
	}

	public void setOutput(Varnode output) {
		this.output = output;
	}

	public ArrayList<Varnode> getInputs() {
		return inputs;
	}

	public void setInputs(ArrayList<Varnode> inputs) {
		this.inputs = inputs;
	}

	public Address getAddress() {
		return address;
	}

	public void setAddress(Address address) {
		this.address = address;
	}

	public PcodeOp getOp() {
		return op;
	}

	public void setOp(PcodeOp op) {
		this.op = op;
	}
}
