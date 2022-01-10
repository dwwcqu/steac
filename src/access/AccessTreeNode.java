package access;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/*
 * 这个访问树节点代表的是访问结构树上的一个结点：可以是内部节点，也可以是叶子结点；
 */
/*
 * 					Serializable接口概述
 * Serializable是java.io包中定义的、用于实现Java类的序列化操作而提供的一个语义级别的接口。
 * Serializable序列化接口没有任何方法或者字段，只是用于标识可序列化的语义。
 * 实现了Serializable接口的类可以被ObjectOutputStream转换为字节流，
 * 同时也可以通过ObjectInputStream再将其解析为对象。
 * 例如，我们可以将序列化对象写入文件后，再次从文件中读取它并反序列化成对象，
 * 也就是说，可以使用表示对象及其数据的类型信息和字节在内存中重新创建对象。
 * 序列化是指把对象转换为字节序列的过程，我们称之为对象的序列化，就是把内存中的这些对象变成一连串的字节(bytes)描述的过程。
 * 而反序列化则相反，就是把持久化的字节文件数据恢复为对象的过程，那么什么情况下需要序列化呢?大概有这样两类比较常见的场景：
 * 		1)、需要把内存中的对象状态数据保存到一个文件或者数据库中的时候，这个场景是比较常见的，例如我们利用mybatis框架编写持久层insert对象数据到数据库中时;
 * 		2)、网络通信时需要用套接字在网络中传送对象时，如我们使用RPC协议进行网络通信时;
 */



public class AccessTreeNode implements java.io.Serializable {
	//以这个结点开始的访问树的叶子结点的个数
	private static int numberOfLeafNodes = 0;
	
	/**
	 * 根据访问策略：int[][]表示；和String[]类型的属性，实现对整个访问树结构的构造
	 */
	public static AccessTreeNode GenerateAccessTree(final int[][] accessPolicy, final String[] rhos) {
		Map<String, String> collisionMap = new HashMap<String, String>();
		for (String rho : rhos) {
			//要求属性值唯一
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
	
	//这个结点的孩子结点
	private final AccessTreeNode[] childNodes;
	//孩子结点需要满足的结点个数
	private final int t;
	//结点的下标
	private final int label;
	//如果这个结点为叶子节点（即，代表的是属性值）
	private final String attribute;
	//保存这个结点是否为叶子节点
	private final boolean isLeafNode;
	
	//叶子节点的构造方法
	private AccessTreeNode(final int i, final String rho) {
		this.childNodes = null;
		this.t = 0;
		this.label = i;
		this.isLeafNode = true;
		this.attribute = rho;
	}
	
	//非叶子节点的构造方法，采用的是递归方法，一直构造到叶子节点为止
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
	 * 给定一个属性集合，用于判断这个属性集合是否满足以这个结点为根节点的访问树的策略
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
	
	//返回t，即阈值
	public int getT() {
		return this.t;
	}
	
	//返回孩子节点的个数
	public int getN() {
		return this.childNodes.length;
	}

	//返回以某个下标的孩子节点
	public AccessTreeNode getChildNodeAt(int index) {
		return this.childNodes[index];
	}
	
	//判断是否为叶子节点
	public boolean isLeafNode() {
		return this.isLeafNode;
	}
	
	//返回叶子节点的属性值
	public String getAttribute() {
		return this.attribute;
	}
	
	//返回这个节点在整个访问结构中的下标
	public int getLabel() {
		return this.label;
	}
	
	//结点之间的判断，相等则放回true，不相等则返回false
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
