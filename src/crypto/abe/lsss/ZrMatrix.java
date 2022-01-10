package crypto.abe.lsss;

import java.math.BigInteger;
import java.util.Vector;

import crypto.abe.LSSSParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class ZrMatrix {
	
private Element[][] zrmatrix;
private int rownum;
private int colnum;
private String[] attrs;
	public ZrMatrix(LSSSParameters lp,Pairing pairing) {
		BigInteger[][] m = lp.getLsssmatrix();
		rownum = m.length;
		colnum = m[0].length;
		zrmatrix = new Element[rownum][colnum];
		for(int i = 0; i < rownum; ++i)
			for(int j =0 ; j < colnum; ++j)
				zrmatrix[i][j] = pairing.getZr().newElement(m[i][j]);
		attrs = new String[lp.getAttrs().size()];
		for(int i = 0; i < attrs.length; ++i)
			attrs[i] = lp.getAttrs().get(i);
	}
	
	public ZrMatrix() {
	}

	public ZrVector multi(ZrVector v) throws Exception
	{
		if(this.colnum != v.getLen())
			throw new Exception("this matrix's column is not equal to vector's length");
		ZrVector re = new ZrVector(this.rownum);
		Element zero = v.getAt(0).duplicate();
		for(int i = 0; i < rownum; ++i){
			zero.setToZero();
			for(int j = 0; j < colnum; ++j) {
				Element temp = zrmatrix[i][j].duplicate();
				zero.add(temp.mul(v.zrvector[j]));
			}
			re.setAt(i, zero);
		}
		return re;
	}
	
	public void swap(int i1,int i2) throws Exception {
		if(i1 < 0 || i1 >= rownum || i2 < 0 || i2 >= rownum)
			throw new Exception("this index is not exist");
		for(int i = 0; i < colnum; ++i) {
			Element temp = zrmatrix[i1][i].duplicate();
			zrmatrix[i1][i] = zrmatrix[i2][i].duplicate();
			zrmatrix[i2][i] = temp.duplicate();
		}
	}
	public ZrVector slove(ZrVector b) throws Exception
	{
		if(this.rownum != b.getLen())
			throw new Exception("this matrix's column is not equal to vector's length");
		
		ZrMatrix Ab = this.combine(b);
		Ab.rowsteptrans();
		//Ab.printMatirx();
		int minRC = (Ab.rownum < Ab.colnum) ? Ab.rownum: Ab.colnum;
		int[] nonZeroIndex = new int[minRC];
		for(int i = 0; i < minRC; ++i)
			nonZeroIndex[i] = Ab.findFirstNonZeroIndexAt(i);
		
		//��ʼ����
		ZrVector solut = new ZrVector();
		solut.len = this.colnum;
		solut.zrvector = new Element[this.colnum];
		for(int i = 0; i < this.colnum; ++i){
			solut.zrvector[i] = b.getAt(0).duplicate();
			solut.zrvector[i].setToZero();
		}
		
		for(int i = minRC - 1; i >= 0; --i) {
			if(nonZeroIndex[i] == Ab.colnum - 1 )
				throw new Exception("this equation hasn't solutions");
			else if(nonZeroIndex[i] == -1)
				continue;
			solut.zrvector[nonZeroIndex[i]] = Ab.zrmatrix[i][Ab.colnum - 1].duplicate();
		}
		return solut;
	}
	
	//�Ծ������ �н��ݱ任
	public void rowsteptrans() throws Exception {
		int minRC = (this.rownum < this.colnum)? rownum : colnum;
		
		for(int i = 0; i < minRC; ++i){
			//�Խ�����Ԫ��Ϊ0
			if(zrmatrix[i][i].isZero()) {
				boolean find = false;
				for(int k = i + 1; k < rownum; ++k) {
					if(!zrmatrix[k][i].isZero()){
						swap(i,k);
						find = true;
						break;
					}
				}
				if(!find) 
					for(int k = 0; k < i; ++k) {
						if(findFirstNonZeroIndexAt(k) == i) {
							swap(k,i);
							break;
						}
					}
				else
					continue;
			}
			//�Խ�����Ԫ�ز�Ϊ1
			else if(!zrmatrix[i][i].isOne()) {
				Element dia = zrmatrix[i][i].duplicate();
				for(int j = i; j < colnum; ++j)
					zrmatrix[i][j].div(dia);
			}
			//�ѶԽ������µ�Ԫ�ر��0
			for(int k = i + 1; k < rownum; ++k) {
				if(zrmatrix[k][i].isZero())
					continue;
				Element dia = zrmatrix[k][i].duplicate();
				for(int j = i; j < colnum; ++j) {
					Element temp = zrmatrix[i][j].duplicate();
					zrmatrix[k][j].sub(temp.mul(dia));
				}
			}
		}
		//����ÿһ�еĵ�һ������Ԫ�ص����±�
		int[] nonZeroIndex = new int[minRC];
		//ͨ����ѭ���ҵ��������±��ͬʱ�����������Ԫ��������������Ԫ�ض���Ϊ0
		for(int i = 0; i < minRC;++i) {
			nonZeroIndex[i] = findFirstNonZeroIndexAt(i);
			if(nonZeroIndex[i] == -1){
				nonZeroIndex[i] = 100;//�����������±�
				continue;
			}
			//�����һ������Ԫ��Ϊ1�����Ϊ1
			else if(!zrmatrix[i][nonZeroIndex[i]].isOne()){
				Element temp = zrmatrix[i][nonZeroIndex[i]].duplicate();
				for(int j = nonZeroIndex[i]; j < colnum; ++j)
					zrmatrix[i][j].div(temp);
			}
			//�ѷ���Ԫ�����Ԫ�ض���Ϊ0
			for(int k = i + 1; k < rownum; ++k) {
				//�÷���Ԫ�����Ԫ���Ѿ�Ϊ0
				if(zrmatrix[k][nonZeroIndex[i]].isZero())
					continue;
				//�÷���Ԫ�����Ԫ�ز�Ϊ0����Ϊ0
				Element temp = zrmatrix[k][nonZeroIndex[i]].duplicate();
				for(int j = nonZeroIndex[i]; j < colnum; ++j)
					zrmatrix[k][j].sub(temp.mul(zrmatrix[i][j]));
			}
		}
		//�Ծ������н��ݽ�����������
		for(int i = 0; i < minRC; ++i) {
			int min = nonZeroIndex[i];
			int minindex = i;
			for(int k = i; k < minRC; ++k){
				if(nonZeroIndex[k] < min){
					minindex = k;
					min = nonZeroIndex[k];
				}
			}
			if(i != minindex) {
				swap(i,minindex);
				int temp = nonZeroIndex[i];
				nonZeroIndex[i] = nonZeroIndex[minindex];
				nonZeroIndex[minindex] = temp;
			}
		}
		//��ÿ�еķ���Ԫ�����Ԫ�ض���Ϊ0
		for(int i = minRC - 1; i >=0; --i) {
			if(nonZeroIndex[i] == 100)
				continue;
			for(int k = i - 1; k >= 0; --k) {
				if(zrmatrix[k][nonZeroIndex[i]].isZero())
					continue;
				Element nonzero = zrmatrix[k][nonZeroIndex[i]].duplicate();
				for(int j = nonZeroIndex[i]; j < colnum; ++j) {
					Element temp = zrmatrix[i][j].duplicate();
					zrmatrix[k][j].sub(temp.mul(nonzero));
				}
			}
		}
	}
	
	
	public ZrMatrix combine(ZrVector v) throws Exception
	{
		if(rownum != v.getLen())
			throw new Exception("the length of vector is not equal to number of matrix's row");
		ZrMatrix re = new ZrMatrix();
		re.rownum = this.rownum;
		re.colnum = this.colnum + 1;
		re.zrmatrix = new Element[this.rownum][this.colnum + 1];
		for(int i = 0; i < this.rownum; ++i) {
			for(int j = 0; j < this.colnum; ++j)
				re.zrmatrix[i][j] = this.zrmatrix[i][j].duplicate();
			re.zrmatrix[i][this.colnum] = v.getAt(i).duplicate();
		}
		return re;
	}
	public int findFirstNonZeroIndexAt(int index) throws Exception
	{
		if(index < 0 || index >= rownum)
			throw new Exception("this index is not exist");
		for(int i = 0; i < colnum; ++i)
		{
			if(!zrmatrix[index][i].isZero())
				return i;
		}
		return -1;
	}
	//�Ծ������ת�ã�������
	public ZrMatrix trans() {
		ZrMatrix zm = new ZrMatrix();
		zm.rownum = this.colnum;
		zm.colnum = this.rownum;
		zm.zrmatrix = new Element[this.colnum][this.rownum];
		for(int i = 0; i < this.rownum; ++i)
			for(int j = 0; j < this.colnum; ++j)
				zm.zrmatrix[j][i] = this.zrmatrix[i][j].duplicate();
		return zm;
	}
	
	private int getAttrIndex(String att) {
		for(int i = 0; i < attrs.length;++i)
			if(attrs[i].equals(att))
				return i;
		return -1;
	}
	
	public ZrMatrix subMatrix(String[] userattr) {
		ZrMatrix sub = new ZrMatrix();
		int subrow = 0;
		for(int i = 0; i < userattr.length; ++i)
			if(getAttrIndex(userattr[i]) != -1)
				++subrow;
		sub.attrs = new String[subrow];
		int[] index = new int[subrow];
		for(int i = 0,j = 0; i < userattr.length; ++i) {
			int id = getAttrIndex(userattr[i]);
			if( id != -1) {
				index[j] = id;
				sub.attrs[j] = userattr[i];
				++j;
			}
		}
		sub.rownum = subrow;
		sub.colnum = this.colnum;
		sub.zrmatrix = new Element[subrow][this.colnum];
		for(int i = 0; i < subrow ; ++i)
			for(int j = 0;  j < this.colnum; ++j) {
				sub.zrmatrix[i][j] = this.zrmatrix[index[i]][j].duplicate();
			}
		return sub;
	}
	
	
	
	public void printMatirx() {
		for(int i = 0; i < rownum; ++i) {
			System.out.print(attrs[i]+" = ");
			for(int j = 0; j <colnum; ++j) {
				System.out.printf("M[%d][%d]=",i+1,j+1);
				System.out.print(zrmatrix[i][j]+"\t");
			}
		System.out.println("");
		}
	}
	public String rho(int index) throws Exception {
		if(index < 0 || index >= attrs.length)
			throw new Exception("row "+ index + " is not exit");
		return attrs[index];
	}
	
	public int getRownum() {
		return rownum;
	}

	public int getColnum() {
		return colnum;
	}

	public String[] getAttrs() {
		return attrs;
	}
	
}
