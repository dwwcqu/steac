package crypto.abe;

import java.math.BigInteger;
import java.util.Stack;
import java.util.Vector;


public class AccessPolicyParser {
	private String policy;
	//判断当前串是否为属性
	private boolean isAttr(String py) {
		if(py.charAt(0) == '(' && py.charAt(py.length() - 1) == ')')
			return false;
		return true;
	}
	
	//对访问策略进行合法性验证
	private boolean isValidPolicy(String policy) throws Exception{
		
		Stack<String> policyStack = new Stack<String>();
		policyStack.push(policy);
		while(!policyStack.isEmpty()) {
			String py = policyStack.pop();
			//如果这个串已经代表属性
			if(isAttr(py)) {
				//保证我们所有属性的取值都是用26位字母表示
				for(int i = 0; i < py.length() - 1; ++i) {
					if(py.charAt(i) < 'A' || (py.charAt(i) > 'Z' && py.charAt(i) < 'a') || py.charAt(i) > 'z') 
						throw new Exception(py + " is not valid");
				}
			}
			
			//这里则代表这个串是一个非叶子节点，需要对其继续进行分析
			else {
				//去掉两边的圆括号
				py = py.substring(1,py.length() - 1);
				int thresholdI = -1;
				int commaI = findFirstComma(py);
				//代表这个串不合法，没有用逗号分开
				if(commaI == -1)
					return false;
				//保证这个非叶子节点的阈值需要是一个整数
				try {
					thresholdI = Integer.parseInt(py.substring(commaI + 1));
				}catch(NumberFormatException e) {
					e.printStackTrace();
				}
				//阈值必须是大于0 的数
				if(thresholdI < 0)
					return false;
				py = py.substring(0,commaI);
				while(py != "") {
					int rightFirstComma = findFirstComma(py);
					//代表这是最后一个结点，则会找不到分隔结点的逗号，直接把这个结点压入栈
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
	
	//在矩阵lsss的第index行开始插入一个矩阵node
	public BigInteger[][] insertMatrixAt(BigInteger[][] oldNode,BigInteger[][] newNode,int index) throws Exception{
		if(index < 0 || index >= oldNode.length)
			throw new Exception(index + " is out range of lsss's row");
		int rOnode = oldNode.length;//旧结点的行数
		int cOnode = oldNode[0].length;//旧结点的列数
		
		int rNnode = newNode.length;//插入结点的行数
		int cNnode = newNode[0].length;//插入结点的列数
		
		int rnnode = rOnode + rNnode - 1;//新结点的行数
		int cnnode = cOnode + cNnode -1;//新结点的列数
		
		BigInteger[][] newnode = new BigInteger[rnnode][cnnode];
		//处理在index之前的行
		for(int i = 0; i < index; ++i) {
			for(int j = 0; j < cnnode ; ++j) {
				if(j < cOnode)
					newnode[i][j] = oldNode[i][j];
				else
					newnode[i][j] = BigInteger.ZERO;
			}
		}
		//处理新插入的 rNnode - 1的行
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
	//根据孩子节点个数和阈值数，返回对应节点的LSSS矩阵
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
	
	//对这个访问策略进行解析，并返回这个策略对应的LSSS矩阵
	public LSSSParameters accessParser() throws Exception{
		Stack<String> pStack = new Stack<String>();
		pStack.push(policy);
		int insertIndex = 0;//插入结点需要的下标
		BigInteger[][] lsss = new BigInteger[1][1];//最后的矩阵
		lsss[0][0] = BigInteger.ONE;
		Vector<String> atts = new Vector<String>();
		while(!pStack.empty()) {
			String py = pStack.pop();
			//如果这个串已经代表属性
			if(isAttr(py)) {
					atts.add(py);
					++insertIndex;
			}
			//这里代表这个还是一个结点
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
					//代表这是最后一个结点，则会找不到分隔结点的逗号，直接把这个结点压入栈
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
