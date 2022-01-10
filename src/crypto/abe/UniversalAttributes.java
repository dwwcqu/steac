package crypto.abe;


public class UniversalAttributes {
	
	private int[][] universalattributes;
	private int attributesCount;
	
	//������Ҫ��������������������ϵͳ��Ҫʹ�õ�������
	public UniversalAttributes(int num) {
		universalattributes = new int[num][num];
		for(int i = 0; i < num; i++)
			for(int j = 0; j < num; j++)
				this.universalattributes[i][j] = j;
		this.attributesCount = num;
	}
	
	
	public int[][] getUniersalAttributes(){
		return this.universalattributes;
	}
	
	
	/**
	 * ����ȫ�ֵ����ԣ�����һ�����ʲ���
	 * @return
	 */
	public int[][] getAccessPolicy(){
		if(this.attributesCount >= 2) {
			int[][] accessPolicy = new int[this.attributesCount][this.attributesCount/2];
			for(int i = 0; i < this.attributesCount; i++)
				for(int j = 0; j < this.attributesCount / 2; j++)
					accessPolicy[i][j] = universalattributes[i][j];
			return accessPolicy;
		}
		else {
			int[][] accessPolicy = new int[attributesCount][1];
			for(int i = 0; i < this.attributesCount; i++)
				accessPolicy[i][0] = this.universalattributes[i][0];
			return accessPolicy;
		}
	}
	
	
	/**
	 * ���ݷ��ʲ��ԣ�����һ��������ʲ��Ե��û����Լ���
	 * @param accesspolicy
	 * @return int[]
	 */
	public int[] getSatisfiedAttributes(int[][] accesspolicy){
		int[] userAttributes = new int[accesspolicy.length];
		for(int i = 0; i < accesspolicy.length; i++)
			userAttributes[i] = accesspolicy[i][0];
		return userAttributes;
	}
}
