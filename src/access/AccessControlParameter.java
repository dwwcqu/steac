package access;

import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/7/19.
 *
 * Generic access control parameters.
 * 这个类的目的在于保存访问结构中的各个参数，包括：整个访问树、访问策略以及这个访问策略的属性集合
 */
public class AccessControlParameter implements CipherParameters, java.io.Serializable {
	
	// The Access Tree
	private final AccessTreeNode rootAccessTreeNode;
	
	// The access policy represented by int array
	protected final int[][] accessPolicy;
	
	// Rho map
	protected final String[] rhos;
	
	/*
	 * 构造方法：使用给定的访问树、访问策略和属性集合进行构造
	 */
	public AccessControlParameter(AccessTreeNode accessTreeNode, int[][] accessPolicy, String[] rhos) {
		this.rootAccessTreeNode = accessTreeNode;
		this.accessPolicy = accessPolicy;
		// Copy rhos
		this.rhos = new String[rhos.length];
		System.arraycopy(rhos, 0, this.rhos, 0, rhos.length);
	}
	
	//返回这个访问树中属性集合
	public String[] getRhos() {
		return this.rhos;
	}
	
	//返回访问策略，以int[][]类型表示
	public int[][] getAccessPolicy() {
		return this.accessPolicy;
	}
	
	/**
	 * 给定一个满足这个访问结构的属性集合，返回这个集合中满足这一访问控制需要的最少属性集合
	 */
	public String[] minSatisfiedAttributeSet(String[] attributes) throws UnsatisfiedAccessControlException {

		if (!this.rootAccessTreeNode.isAccessControlSatisfied(attributes)) {
			throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
		}

		boolean[] isRedundantAttribute = new boolean[attributes.length];
		int numOfMinAttributeSet = attributes.length;
		for (int i = 0; i < isRedundantAttribute.length; i++) {
			isRedundantAttribute[i] = true;
			numOfMinAttributeSet--;
			String[] minAttributeSet = new String[numOfMinAttributeSet];
			for (int j = 0, k = 0; j < attributes.length; j++) {
				if (!isRedundantAttribute[j]) {
					minAttributeSet[k] = attributes[j];
					k++;
				}
			}
			if (!this.rootAccessTreeNode.isAccessControlSatisfied(minAttributeSet)) {
				numOfMinAttributeSet++;
				isRedundantAttribute[i] = false;
			}
		}
		String[] minAttributeSet = new String[numOfMinAttributeSet];
		for (int j = 0, k = 0; j < attributes.length; j++) {
			if (!isRedundantAttribute[j]) {
				minAttributeSet[k] = attributes[j];
				k++;
			}
		}
		return minAttributeSet;
	}
	
	/*
	 * 返回这个访问策略中的访问树，以AccessTreeNode类型表示（为一种递归结构）
	 */
	public AccessTreeNode getRootAccessTreeNode() {
		return this.rootAccessTreeNode;
	}
	
	//判断两个访问控制参数对象是否一样，相同返回true，不相同返回false
	@Override
	public boolean equals(Object anObject) {
		if (this == anObject) {
			return true;
		}
		if (anObject instanceof AccessControlParameter) {
			AccessControlParameter that = (AccessControlParameter) anObject;
			// Compare rhos
			if (!Arrays.equals(this.rhos, that.getRhos())) {
				return false;
			}
			// Compare access policy
			if (this.accessPolicy.length != that.getAccessPolicy().length) {
				return false;
			}
			for (int i = 0; i < this.accessPolicy.length; i++) {
				if (!Arrays.equals(this.accessPolicy[i], that.getAccessPolicy()[i])) {
					return false;
				}
			}
			// Compare AccessTreeNode
			return this.rootAccessTreeNode.equals(that.getRootAccessTreeNode());
		}
		return false;
	}
}

