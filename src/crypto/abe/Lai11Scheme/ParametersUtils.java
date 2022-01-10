package crypto.abe.Lai11Scheme;

public class ParametersUtils {
	
	/**
	 * ����������������ϵͳʹ�õ����Կռ�
	 * ������������������������
	 * �������������������������е�����ֵ����
	 * �������Ӿ�Ϊһ����
	 * 			�������������ԣ���ÿ������������ĸ�����ֵ
	 */
	public static int[][] universal_attributes_example_one = {
			{0,1,2,3},
			{0,1,2,3},
			{0,1,2,3},
			{0,1,2,3}
	};
	
	/*
	 * Ϊexampleone��һ�����ʿ��Ʋ���
	 * �к�Ϊ��������к�Ϊ��������һ������������ֵ���������������intֵΪ��������ֵ�ڴ������Ե�����ֵ���±�
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








