package crypto.abe;

import java.math.BigInteger;
import java.util.Stack;
import java.util.Vector;


public class AccessPolicyParser {
	private String policy;
	//�жϵ�ǰ���Ƿ�Ϊ����
	private boolean isAttr(String py) {
		if(py.charAt(0) == '(' && py.charAt(py.length() - 1) == ')')
			return false;
		return true;
	}
	
	//�Է��ʲ��Խ��кϷ�����֤
	private boolean isValidPolicy(String policy) throws Exception{
		
		Stack<String> policyStack = new Stack<String>();
		policyStack.push(policy);
		while(!policyStack.isEmpty()) {
			String py = policyStack.pop();
			//���������Ѿ���������
			if(isAttr(py)) {
				//��֤�����������Ե�ȡֵ������26λ��ĸ��ʾ
				for(int i = 0; i < py.length() - 1; ++i) {
					if(py.charAt(i) < 'A' || (py.charAt(i) > 'Z' && py.charAt(i) < 'a') || py.charAt(i) > 'z') 
						throw new Exception(py + " is not valid");
				}
			}
			
			//����������������һ����Ҷ�ӽڵ㣬��Ҫ����������з���
			else {
				//ȥ�����ߵ�Բ����
				py = py.substring(1,py.length() - 1);
				int thresholdI = -1;
				int commaI = findFirstComma(py);
				//������������Ϸ���û���ö��ŷֿ�
				if(commaI == -1)
					return false;
				//��֤�����Ҷ�ӽڵ����ֵ��Ҫ��һ������
				try {
					thresholdI = Integer.parseInt(py.substring(commaI + 1));
				}catch(NumberFormatException e) {
					e.printStackTrace();
				}
				//��ֵ�����Ǵ���0 ����
				if(thresholdI < 0)
					return false;
				py = py.substring(0,commaI);
				while(py != "") {
					int rightFirstComma = findFirstComma(py);
					//�����������һ����㣬����Ҳ����ָ����Ķ��ţ�ֱ�Ӱ�������ѹ��ջ
					if(rightFirstComma == -1) {
						policyStack.push(py);
						py = "";
					}
					else {
						policyStack.push(py.substring(rightFirstComma + 1));
						py = py.substring(0,rightFirstComma);
					}
				}
			}
			
		}
		
		return true;
	}
	
	private int findFirstComma(String str) {
		int lPara = 0;
		int rPara = 0;
		for(int i = str.length() - 1; i >=0; --i) {
			if(str.charAt(i) == ')')
				++lPara;
			else if(str.charAt(i) == '(')
				++rPara;
			else if(lPara == rPara && str.charAt(i) == ',')
				return i;
		}
		return -1;
	}
	
	//�ھ���lsss�ĵ�index�п�ʼ����һ������node
	public BigInteger[][] insertMatrixAt(BigInteger[][] oldNode,BigInteger[][] newNode,int index) throws Exception{
		if(index < 0 || index >= oldNode.length)
			throw new Exception(index + " is out range of lsss's row");
		int rOnode = oldNode.length;//�ɽ�������
		int cOnode = oldNode[0].length;//�ɽ�������
		
		int rNnode = newNode.length;//�����������
		int cNnode = newNode[0].length;//�����������
		
		int rnnode = rOnode + rNnode - 1;//�½�������
		int cnnode = cOnode + cNnode -1;//�½�������
		
		BigInteger[][] newnode = new BigInteger[rnnode][cnnode];
		//������index֮ǰ����
		for(int i = 0; i < index; ++i) {
			for(int j = 0; j < cnnode ; ++j) {
				if(j < cOnode)
					newnode[i][j] = oldNode[i][j];
				else
					newnode[i][j] = BigInteger.ZERO;
			}
		}
		//�����²���� rNnode - 1����
		for(int i = index; i < index + rNnode; ++i)
			for(int j = 0; j < cnnode; ++j) {
				if(j < cOnode) 
					newnode[i][j] = oldNode[index][j].multiply(newNode[i - index][0]);
				else 
					newnode[i][j] = newNode[i - index][j - cOnode + 1];
			}
		
		for(int i = index + rNnode; i < rnnode; ++i) {
			for(int j = 0; j < cnnode ; ++j) {
				if(j < cOnode)
					newnode[i][j] = oldNode[i - rNnode + 1][j];
				else
					newnode[i][j] = BigInteger.ZERO;
			}
		}
		return newnode;
	}
	//return n^p
	private BigInteger getPow(BigInteger n,int p) {
		return n.pow(p);
	}
	//���ݺ��ӽڵ��������ֵ�������ض�Ӧ�ڵ��LSSS����
	public BigInteger[][] getNode(int threshold, int childnum){
		BigInteger[][] node = new BigInteger[childnum][threshold];
		for(int i = 1; i <= childnum; ++i)
			for(int j = 0; j < threshold; ++j)
				node[i-1][j] = getPow(BigInteger.valueOf(i), j);
		return node;
	}
	
	public AccessPolicyParser(String policy) throws Exception {
		if(isValidPolicy(policy))
			this.policy = policy;
	}
	
	public void printintmatrix(BigInteger[][] matrix) {
		for(int i = 0; i < matrix.length; ++i) {
			for(int j = 0; j < matrix[0].length; ++j)
				System.out.print(matrix[i][j].toString(10) + "\t");
			System.out.println("");
		}
	}
	
	//��������ʲ��Խ��н�����������������Զ�Ӧ��LSSS����
	public LSSSParameters accessParser() throws Exception{
		Stack<String> pStack = new Stack<String>();
		pStack.push(policy);
		int insertIndex = 0;//��������Ҫ���±�
		BigInteger[][] lsss = new BigInteger[1][1];//���ľ���
		lsss[0][0] = BigInteger.ONE;
		Vector<String> atts = new Vector<String>();
		while(!pStack.empty()) {
			String py = pStack.pop();
			//���������Ѿ���������
			if(isAttr(py)) {
					atts.add(py);
					++insertIndex;
			}
			//��������������һ�����
			else {
				py = py.substring(1,py.length() - 1);
				int threshold = -1;
				int commaI = findFirstComma(py);
				try {
					threshold = Integer.parseInt(py.substring(commaI + 1));
				}catch(NumberFormatException e) {
					e.printStackTrace();
				}
				int childnum = 0;
				py = py.substring(0,commaI);
				while(py != "") {
					int rightFirstComma = findFirstComma(py);
					//�����������һ����㣬����Ҳ����ָ����Ķ��ţ�ֱ�Ӱ�������ѹ��ջ
					if(rightFirstComma == -1) {
						pStack.push(py);
						py = "";
						childnum++;
					}
					else {
						pStack.push(py.substring(rightFirstComma + 1));
						py = py.substring(0,rightFirstComma);
						childnum++;
					}
				}
				lsss = insertMatrixAt(lsss, getNode(threshold, childnum), insertIndex);
			}
				
		}
		
		return new LSSSParameters(lsss, atts);
	}
}
