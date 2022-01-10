package crypto.abe;

import java.math.BigInteger;
import java.util.Vector;

public class LSSSParameters {
	private BigInteger[][] lsssmatrix;
	private Vector<String> attrs;
	public LSSSParameters(BigInteger[][] l,Vector<String> a) {
		this.lsssmatrix = l;
		this.attrs = a;
	}
	
	public BigInteger[][] getLsssmatrix() {
		return lsssmatrix;
	}
	public Vector<String> getAttrs() {
		return attrs;
	}
	public void printInform() {
		if(attrs.size() != lsssmatrix.length)
			System.out.println("Errors in LSSSParameters");
		for(int i = 0; i < attrs.size(); ++i) {
			System.out.print(attrs.get(i) + " = ");
			for(int j = 0; j < lsssmatrix[0].length; ++j)
				System.out.print(lsssmatrix[i][j] + "\t");
			System.out.println("");
		}
	}
}
