package crypto.abe.Lai11Scheme;

public class ParametersUtils {
	
	/**
	 * 此数组代表的是整个系统使用的属性空间
	 * 数组的行数代表属性类别数量
	 * 数组的列数代表此类属性所具有的属性值数量
	 * 如下例子就为一个：
	 * 			有四中类别的属性，且每中属性类别有四个属性值
	 */
	public static int[][] universal_attributes_example_one = {
			{0,1,2,3},
			{0,1,2,3},
			{0,1,2,3},
			{0,1,2,3}
	};
	
	/*
	 * 为exampleone的一个访问控制策略
	 * 行号为属性类别，列号为代表了这一类别允许的属性值的数量；而具体的int值为此类属性值在此类属性的属性值的下标
	 */
	public static int[][] access_policy_example_one = {
			{0,1,2},
			{1,3},
			{0,1},
			{2,3}
	};
	
	public static int[] user_attributes_satisfied_example_one_01 = {
			1,1,1,2
	};
	public static int[] user_attributes_satisfied_example_one_02 = {
			1,3,0,3
	};
	public static int[] user_attributes_unsatisfied_example_one_01 = {
			3,2,1,2
	};
	public static int[] user_attributes_unsatisfied_example_one_02 = {
			2,2,3,1
	};
	
	public static boolean is_in_access_policy(int[][] accessPolicy, int i, int index) throws Exception {
		
		if(i < 0 || i >= accessPolicy.length)
			throw new Exception("over the array");
		
		for(int j = 0; j < accessPolicy[i].length; j++) {
			if(accessPolicy[i][j] == index)
				return true;
		}
		return false;
	}
}








