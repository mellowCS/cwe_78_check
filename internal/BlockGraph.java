package internal;

import java.util.ArrayList;

import ghidra.program.model.address.Address;


public class BlockGraph {
	private ArrayList<Block> graph;
	
	public BlockGraph() {}
	
	public BlockGraph(ArrayList<Block> blocks) {
		this.graph = blocks;
	}

	public ArrayList<Block> getGraph() {
		return graph;
	}

	public void setGraph(ArrayList<Block> graph) {
		this.graph = graph;
	}
	
	public void addBlock(Block block) {
		this.graph.add(block);
	}
	
	public Block getBlockByAddress(Address address) {
		for(Block block : graph) {
			if(block.getAddresses().contains(address)) {
				return block;
			}
		}
		
		return null;
	}
}
