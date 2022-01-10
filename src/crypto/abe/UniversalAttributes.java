package crypto.abe;


public class UniversalAttributes {
	
	private int[][] universalattributes;
	private int attributesCount;
	
	//根据需要的属性数量，生成整个系统需要使用的属性量
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
	 * 根据全局的属性，生成一个访问策略
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
	 * 根据访问策略，生成一个满足访问策略的用户属性集合
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
