package access;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/*
 * ����������ڵ������Ƿ��ʽṹ���ϵ�һ����㣺�������ڲ��ڵ㣬Ҳ������Ҷ�ӽ�㣻
 */
/*
 * 					Serializable�ӿڸ���
 * Serializable��java.io���ж���ġ�����ʵ��Java������л��������ṩ��һ�����弶��Ľӿڡ�
 * Serializable���л��ӿ�û���κη��������ֶΣ�ֻ�����ڱ�ʶ�����л������塣
 * ʵ����Serializable�ӿڵ�����Ա�ObjectOutputStreamת��Ϊ�ֽ�����
 * ͬʱҲ����ͨ��ObjectInputStream�ٽ������Ϊ����
 * ���磬���ǿ��Խ����л�����д���ļ����ٴδ��ļ��ж�ȡ���������л��ɶ���
 * Ҳ����˵������ʹ�ñ�ʾ���������ݵ�������Ϣ���ֽ����ڴ������´�������
 * ���л���ָ�Ѷ���ת��Ϊ�ֽ����еĹ��̣����ǳ�֮Ϊ��������л������ǰ��ڴ��е���Щ������һ�������ֽ�(bytes)�����Ĺ��̡�
 * �������л����෴�����ǰѳ־û����ֽ��ļ����ݻָ�Ϊ����Ĺ��̣���ôʲô�������Ҫ���л���?�������������Ƚϳ����ĳ�����
 * 		1)����Ҫ���ڴ��еĶ���״̬���ݱ��浽һ���ļ��������ݿ��е�ʱ����������ǱȽϳ����ģ�������������mybatis��ܱ�д�־ò�insert�������ݵ����ݿ���ʱ;
 * 		2)������ͨ��ʱ��Ҫ���׽����������д��Ͷ���ʱ��������ʹ��RPCЭ���������ͨ��ʱ;
 */



public class AccessTreeNode implements java.io.Serializable {
	//�������㿪ʼ�ķ�������Ҷ�ӽ��ĸ���
	private static int numberOfLeafNodes = 0;
	
	/**
	 * ���ݷ��ʲ��ԣ�int[][]��ʾ����String[]���͵����ԣ�ʵ�ֶ������������ṹ�Ĺ���
	 */
	public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) {
		Map<String, String> collisionMap = new HashMap<String, String>();
		for (String rho : rhos) {
			//Ҫ������ֵΨһ
			if (collisionMap.containsKey(rho)) {
				throw new InvalidParameterException("Invalid access policy, rhos containing identical string: " + rho);
			} else {
				collisionMap.put(rho, rho);
			}
		}
		numberOfLeafNodes = 0;
		AccessTreeNode rootAccessTreeNode = new AccessTreeNode(accessPolicy, 0, rhos);
		if (numberOfLeafNodes != rhos.length) {
			throw new InvalidParameterException("Invalid access policy, number of leaf nodes " + numberOfLeafNodes
					+ " does not match number of rhos " + rhos.length);
		}
		return rootAccessTreeNode;
	}
	
	//������ĺ��ӽ��
	private final AccessTreeNode[] childNodes;
	//���ӽ����Ҫ����Ľ�����
	private final int t;
	//�����±�
	private final int label;
	//���������ΪҶ�ӽڵ㣨���������������ֵ��
	private final String attribute;
	//�����������Ƿ�ΪҶ�ӽڵ�
	private final boolean isLeafNode;
	
	//Ҷ�ӽڵ�Ĺ��췽��
	private AccessTreeNode(final int i, final String rho) {
		this.childNodes = null;
		this.t = 0;
		this.label = i;
		this.isLeafNode = true;
		this.attribute = rho;
	}
	
	//��Ҷ�ӽڵ�Ĺ��췽�������õ��ǵݹ鷽����һֱ���쵽Ҷ�ӽڵ�Ϊֹ
	private AccessTreeNode(final int[][] accessPolicy, final int i, final String[] rhos) {
		int[] accessPolicyNode = accessPolicy[i];
		if (accessPolicyNode[0] < accessPolicyNode[1]) {
			throw new InvalidParameterException("Invalid access policy, n < t in the threahold gate " + i);
		}
		this.childNodes = new AccessTreeNode[accessPolicyNode[0]];
		this.t = accessPolicyNode[1];
		this.label = i;
		this.attribute = null;
		this.isLeafNode = false;
		int k = 0;
		for (int j = 2; j < accessPolicyNode.length; j++) {
			if (accessPolicyNode[j] > 0) {
				this.childNodes[k] = new AccessTreeNode(accessPolicy, accessPolicyNode[j], rhos);
			} else if (accessPolicyNode[j] < 0) {
				numberOfLeafNodes++;
				this.childNodes[k] = new AccessTreeNode(accessPolicyNode[j], rhos[-accessPolicyNode[j] - 1]);
			} else {
				throw new InvalidParameterException("Invalid access policy, containing access node with index 0");
			}
			k++;
		}
	}
	
	/**
	 * ����һ�����Լ��ϣ������ж�������Լ����Ƿ�������������Ϊ���ڵ�ķ������Ĳ���
	 */
	boolean isAccessControlSatisfied(final String[] attributes) {
//		System.out.println("isAccessControlSatisfied");
//		for (int i = 0; i < attributes.length; i++) {
//			System.out.print(attributes[i]);
//			if (i < attributes.length - 1) {
//				System.out.print(", ");
//			}
//		}
//		System.out.println();
//		System.out.println("Threshold: " + this.t);

		if (!this.isLeafNode) {
			int satisfiedChildNumber = 0;
			for (AccessTreeNode childNode : this.childNodes) {
				if (childNode.isAccessControlSatisfied(attributes)) {
					satisfiedChildNumber++;
				}
			}
			return (satisfiedChildNumber >= t);
		} else {
			for (String eachAttribute : attributes) {
				if (this.attribute.equals(eachAttribute)) {
					return true;
				}
			}
			return false;
		}
	}
	
	//����t������ֵ
	public int getT() {
		return this.t;
	}
	
	//���غ��ӽڵ�ĸ���
	public int getN() {
		return this.childNodes.length;
	}

	//������ĳ���±�ĺ��ӽڵ�
	public AccessTreeNode getChildNodeAt(int index) {
		return this.childNodes[index];
	}
	
	//�ж��Ƿ�ΪҶ�ӽڵ�
	public boolean isLeafNode() {
		return this.isLeafNode;
	}
	
	//����Ҷ�ӽڵ������ֵ
	public String getAttribute() {
		return this.attribute;
	}
	
	//��������ڵ����������ʽṹ�е��±�
	public int getLabel() {
		return this.label;
	}
	
	//���֮����жϣ������Ż�true��������򷵻�false
	@Override
	public boolean equals(Object anOjbect) {
		if (this == anOjbect) {
			return true;
		}
		if (anOjbect instanceof AccessTreeNode) {
			AccessTreeNode that = (AccessTreeNode) anOjbect;
			// Compare t;
			if (this.t != that.getT()) {
				return false;
			}
			// Compare label
			if (this.label != that.getLabel()) {
				return false;
			}
			// Compare leafnode
			if (this.isLeafNode) {
				// Compare attribute
				if (!this.attribute.equals(that.attribute)) {
					return false;
				}
				return this.isLeafNode == that.isLeafNode;
			} else {
				// Compare nonleaf nodes
				if (this.childNodes.length != that.childNodes.length) {
					return false;
				}
				for (int i = 0; i < this.childNodes.length; i++) {
					// Compare child nodes
					if (!this.childNodes[i].equals(that.getChildNodeAt(i))) {
						return false;
					}
				}
				return true;
			}
		}
		return false;
	}
}
