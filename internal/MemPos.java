package internal;

import ghidra.program.model.pcode.Varnode;

public class MemPos {
	private Varnode register;
	private Varnode offset;
	
	public MemPos(Varnode register, Varnode offset) {
		this.setRegister(register);
		this.setOffset(offset);
	}

	public Varnode getOffset() {
		return offset;
	}

	public void setOffset(Varnode offset) {
		this.offset = offset;
	}

	public Varnode getRegister() {
		return register;
	}

	public void setRegister(Varnode register) {
		this.register = register;
	}
}
