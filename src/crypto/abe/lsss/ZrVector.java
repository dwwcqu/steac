package crypto.abe.lsss;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;


public class ZrVector {
	protected  Element[] zrvector;
	protected int len;
	
	public ZrVector(){
		
	}
	public ZrVector(int len){
		this.len= len;
		zrvector = new Element[len];
	}
	public ZrVector(int len,Pairing pairing,Cate c) {
		this.len = len;
		this.zrvector = new Element[len];
		if(c == Cate.Random)
			for(int i = 0; i < len; ++i)
			{
				zrvector[i] = pairing.getZr().newRandomElement();
			}
		else if(c==Cate.Special){
			zrvector[0] = pairing.getZr().newElement(1);
			for(int i = 1; i < len; ++i)
				zrvector[i] = pairing.getZr().newElement(0);
		}
	}

	public int getLen() {
		return len;
	}
	
	public Element getAt(int index) throws Exception
	{
		if(index < 0 || index >= len)
			throw new Exception("index" + index + "is out range of " + len);
		return this.zrvector[index];
	}
	void setAt(int index,Element e) throws Exception{
		if(index < 0 || index >= len)
			throw new Exception("index" + index + "is out range of " + len);
		zrvector[index] = e.duplicate();
	}
	//向量内积
	public Element multi(ZrVector zv) throws Exception {
		if(this.len != zv.getLen())
			throw new Exception("the vector's length is not same");
		Element zero = zv.getAt(0).duplicate();
		zero.setToZero();
		for(int i = 0; i < this.len;++i) {
			Element temp = zrvector[i].duplicate();
			zero.add(temp.mul(zv.getAt(i)));
		}
		return zero;
	}
	
	public void printVector() {
		for(int i = 0; i < len;++i)
		{
			System.out.printf("V[%d]=",i+1);
			System.out.print(zrvector[i]+"\n");
		}
	}
}
