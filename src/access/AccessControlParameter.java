package access;

import java.util.Arrays;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/7/19.
 *
 * Generic access control parameters.
 * ������Ŀ�����ڱ�����ʽṹ�еĸ������������������������������ʲ����Լ�������ʲ��Ե����Լ���
 */
public class AccessControlParameter implements CipherParameters, java.io.Serializable {
	
	// The Access Tree
	private final AccessTreeNode rootAccessTreeNode;
	
	// The access policy represented by int array
	protected final int[][] accessPolicy;
	
	// Rho map
	protected final String[] rhos;
	
	/*
	 * ���췽����ʹ�ø����ķ����������ʲ��Ժ����Լ��Ͻ��й���
	 */
	public AccessControlParameter(AccessTreeNode accessTreeNode, int[][] accessPolicy, String[] rhos) {
		this.rootAccessTreeNode = accessTreeNode;
		this.accessPolicy = accessPolicy;
		// Copy rhos
		this.rhos = new String[rhos.length];
		System.arraycopy(rhos, 0, this.rhos, 0, rhos.length);
	}
	
	//������������������Լ���
	public String[] getRhos() {
		return this.rhos;
	}
	
	//���ط��ʲ��ԣ���int[][]���ͱ�ʾ
	public int[][] getAccessPolicy() {
		return this.accessPolicy;
	}
	
	/**
	 * ����һ������������ʽṹ�����Լ��ϣ��������������������һ���ʿ�����Ҫ���������Լ���
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
	 * ����������ʲ����еķ���������AccessTreeNode���ͱ�ʾ��Ϊһ�ֵݹ�ṹ��
	 */
	public AccessTreeNode getRootAccessTreeNode() {
		return this.rootAccessTreeNode;
	}
	
	//�ж��������ʿ��Ʋ��������Ƿ�һ������ͬ����true������ͬ����false
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

