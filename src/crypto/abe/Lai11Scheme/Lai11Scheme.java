package crypto.abe.Lai11Scheme;

import java.io.FileOutputStream;

import crypto.abe.Utils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

public class Lai11Scheme {
	
	public static void main(String[] args) throws Exception {
		
		FileOutputStream os = new FileOutputStream("src//crypto//abe//Performance//Lai11Scheme.xls");
		//创建Excel工作薄
		WritableWorkbook file1 = Workbook.createWorkbook(os);
		//创建工作薄上面的一个工作表
		WritableSheet ws = file1.createSheet("Lai11Scheme", 0);
		
		String[] titles = {
							"Round Number","SetUp Time",
							"KeyGen Time","Encryption Time",
				           "Decryption Time","Total Time"
				           };
		for(int i = 0; i < titles.length;i++) {
			Label lable = new Label(i, 0, titles[i]);
			ws.addCell(lable);
		}
		
		int roundCount = 100;
		//记录每个阶段所用的时间的平均值
		double[] averageTime = new double[5];
		for(int i = 0; i < 5; i++)
			averageTime[i] = 0;
		for(int k = 1; k <= roundCount; k++) {
			//四个计时器用于记录四个过程所用的时间
			long[] timer = new long[4];
			System.out.println("################################### Setup Begin ########################################");
			timer[0] = System.nanoTime();
			//系统的全局属性表示
			int[][] universalAttrs = Utils.universal_attributes_example_one;
			//生成系统的配对代数结构
			PropertiesParameters propertiesP = new PropertiesParameters().load("params//a1_3_128.properties");
			Pairing pairing = PairingFactory.getPairing(propertiesP);
			
			//G群上面的生成元
			Element generator = pairing.getG1().newRandomElement().getImmutable();
			
			//Gp子群上面的生成元gp
			Element gp = ElementUtils.getGenerator(pairing, generator, propertiesP, 0, 3);
			
			//Gr子群上面的生成元gr
			Element gr = ElementUtils.getGenerator(pairing, generator, propertiesP, 1, 3);
			
			//系统的主秘钥
			Element[][] a = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//Rij 为群Gr上的元素
			Element[][] R = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//系统公共参数 Aij = gp^aij * Rij，即每个属性的每个属性值都分配了一个公共参数
			Element[][] A = new Element[universalAttrs.length][universalAttrs[0].length];
			for(int i = 0; i < universalAttrs.length; i++) 
				for(int j = 0; j < universalAttrs[0].length; j++) {
					a[i][j] = pairing.getZr().newRandomElement().getImmutable();
					R[i][j] = ElementUtils.randomIn(pairing, gr);
					A[i][j] = gp.powZn(a[i][j]).mul(R[i][j]);
				}
			
			//Ro
			Element R0 = ElementUtils.randomIn(pairing, gr);
			
			//omega
			Element omega = pairing.getZr().newRandomElement().getImmutable();
			
			//A0 = gp * R0
			Element A0 = gp.mul(R0);
			
			//Y = = e(gp,gp) ^ omega
			Element Y = pairing.pairing(gp, gp).powZn(omega);
			
			timer[0] = System.nanoTime() - timer[0];
			System.out.println("################################### Setup End #########################################");
			
			System.out.println("################################### KeyGen Begin #######################################");
			timer[1] = System.nanoTime();
			
			//用户的属性集合，用一个一维数组表示，每个数组值代表在每个类属性的属性下标
			int[] userAttrs = Utils.user_attributes_satisfied_example_one_01;
			
			//Di，即用户的每个属性，系统都会分配给一个钥匙
			Element[] D = new Element[userAttrs.length];
			Element[] ti = new Element[userAttrs.length];
			Element t = pairing.getZr().newZeroElement();
			for(int i = 0; i < userAttrs.length; i++) {
				ti[i] = pairing.getZr().newRandomElement().getImmutable();
				t = t.add(ti[i]);
				D[i] = gp.powZn(ti[i].mul(a[i][userAttrs[i]].invert()));
			}
			
			//D0
			Element D0 = gp.powZn(omega.sub(t));
			timer[1] = System.nanoTime() - timer[1];
			System.out.println("################################### KeyGen End #########################################");
			
			System.out.println("################################### Encryption Begin ###################################");
			timer[2] = System.nanoTime();
			
			/*
			 * 加密阶段使用的访问策略，用二维数组表示；
			 * 行号代表属性类别的下标，列代表这类属性给定的属性数量；
			 * 其中数组的值为没类属性的属性值在当前属性类别的下标
			 */
			int[][] accessPolicy = Utils.access_policy_example_one;
			
			//GT群上的随机元素代表被加密的数据M
			Element M = pairing.getGT().newRandomElement().getImmutable();
			
			//s，加密阶段随机选取的一个Zr上的元素
			Element S = pairing.getZr().newRandomElement().getImmutable();
			
			//R0'
			Element R0_ = ElementUtils.randomIn(pairing, gr);
			
			//sij
			Element[][] s = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//Rij'
			Element[][] R_ = new Element[universalAttrs.length][universalAttrs[0].length];
			
			/*
			 * 针对每个属性类的每个属性值
			 * 若此属性值位于访问控制策略中，则Cij = Aij ^ s * Rij'
			 * 否则，Cij = Aij ^ sij * Rij'
			 */
			Element[][] C = new Element[universalAttrs.length][universalAttrs[0].length];
			for(int i = 0; i < universalAttrs.length; i++)
				for(int j = 0; j < universalAttrs[0].length; j++) {
					s[i][j] = pairing.getZr().newRandomElement().getImmutable();
					R_[i][j] = ElementUtils.randomIn(pairing, gr);
					if(ParametersUtils.is_in_access_policy(accessPolicy, i, j))
						C[i][j] = A[i][j].powZn(S).mul(R_[i][j]);
					else
						C[i][j] = A[i][j].powZn(s[i][j]).mul(R_[i][j]);
				}
			
			//C0 = A0 ^ S * R0'
			Element C0 = A0.powZn(S).mul(R0_);
			
			//C' = M * Y ^ S = M * e(gp,gp) ^ (omega * S)
			Element C_ = M.mul(Y.powZn(S));
			timer[2] = System.nanoTime() - timer[2];
			System.out.println("################################### Encryption End #####################################");
			
			System.out.println("################################### Decryption Begin ###################################");
			timer[3] = System.nanoTime();
			//e(C0,D0)
			Element CD0 = pairing.pairing(C0, D0);
			
			//Pai[e(Ciji,Di)]，即根据接收方的每个属性值（用属性下标表示）以及对应的钥匙，还原出密钥分配阶段秘密值
			Element CD = pairing.getGT().newOneElement();
			for(int i = 0; i < userAttrs.length; i++)
				CD = CD.mul(pairing.pairing(C[i][userAttrs[i]],D[i]));
			
			//M = C' / e(C0,D0) * Pai[e(Ciji,Di)]
			Element M_ = C_.mul(CD0.mul(CD).invert());
			timer[3] = System.nanoTime() - timer[3];
			System.out.println("################################### Decryption End #####################################");
			if(M.equals(M_)) {
				double totalTime = 0;
				for(int i = 0; i < timer.length; i++) {
					totalTime += (double)timer[i] / 1000000000L;
					averageTime[i] += (double)timer[i] / 1000000000L;
				}
				averageTime[4] += totalTime;
				
				//保存时间为String类型，以便于写入Excel中
				String[] timeRecords = new String[5];
				for(int i = 0; i < timer.length; i++)
					timeRecords[i] = String.valueOf((double)timer[i] / 1000000000L);
				timeRecords[4] = String.valueOf(totalTime);
				
				Label index = new Label(0,k,String.valueOf(k));
				ws.addCell(index);
				for(int j = 1; j < titles.length; j++){
					Label l = new Label(j,k,timeRecords[j-1]);
					ws.addCell(l);
				}
				
			}
			else {
				System.out.println("Round "+ k +"decryption is not correct!\n");
				throw new Exception("Decryption is not correct!");
			}
		}
		int excelRows = ws.getRows();
		Label ave = new Label(0,excelRows,"Average Time");
		ws.addCell(ave);
		
		for(int i = 1; i < 6; i++) {
			averageTime[i-1] /= roundCount;
			Label aveT = new Label(i,excelRows,String.valueOf(averageTime[i-1]));
			ws.addCell(aveT);
		}
		
		file1.write();
		file1.close();
	}
	
}
