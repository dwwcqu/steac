package crypto.abe.GPZMM20Scheme;

import java.io.FileOutputStream;

import crypto.abe.Utils;
import crypto.abe.Lai11Scheme.ParametersUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

public class test {
	
	
	public static void main(String[] args) throws Exception {
		
		FileOutputStream os = new FileOutputStream("src//crypto//abe//Performance.xls");
		
		//����Excel������
		WritableWorkbook file1 = Workbook.createWorkbook(os);
		//���������������һ��������
		WritableSheet ws = file1.createSheet("GPZMM20Scheme", 0);
		
		String[] titles = {
							"Round Number","SetUp Time",
						   "Encryption Time","KeyGen Time",
				           "Decryption Time","ToTal Time"
				           };
		for(int i = 0; i < titles.length;i++) {
			Label lable = new Label(i, 0, titles[i]);
			ws.addCell(lable);
		}
		
		long[] timer = new long[4];
		
		int roundCount = 100;
		double[] averageTime = new double[5];
		for(int i = 0; i < 5; i++)
			averageTime[i] = 0;
		for(int k = 1; k <= roundCount; k++) {
			System.out.println("################################### Setup Begin ########################################");
			timer[0] = System.nanoTime();
			
			//ϵͳ��ȫ������
			int[][] universalAttrs = Utils.universal_attributes_example_one;
			
			//��Բ���������
			PropertiesParameters propertiesP = new PropertiesParameters().load("params//a1_3_128.properties");
			Pairing pairing = PairingFactory.getPairing(propertiesP);
			
			//ȺG���������Ԫ
			Element generator = pairing.getG1().newRandomElement().getImmutable();
			
			//ȺG����ȺGp������Ԫ
			Element gp = ElementUtils.getGenerator(pairing, generator, propertiesP, 0, 3);
			
			//ȺG����ȺGr������Ԫ
			Element gr = ElementUtils.getGenerator(pairing, generator, propertiesP, 1, 3);
			
			//����Կa
			Element a = pairing.getZr().newRandomElement().getImmutable();
			
			//����Կomega
			Element omega = pairing.getZr().newRandomElement().getImmutable();
			
			//��������
			Element R0 = ElementUtils.randomIn(pairing, gr);
			Element R1 = ElementUtils.randomIn(pairing, gr);
			Element A0 = gp.mul(R0);
			Element A1 = gp.powZn(a).mul(R1);
			Element Y = pairing.pairing(gp, gp).powZn(omega);
			timer[0] = System.nanoTime() - timer[0];
			System.out.println("################################### Setup End #######################################");
			
			System.out.println("################################### Encryption Begin ###################################");
			timer[1] = System.nanoTime();
			
			//����ʹ�õķ��ʿ���
			int[][] accessPolicy = ParametersUtils.access_policy_example_one;
			
			//ȺGT�ϵ�Ԫ�ش���һ������ʹ�õ�����
			Element M = pairing.getGT().newRandomElement().getImmutable();
			
			//��ȡ����
			Element S = pairing.getZr().newRandomElement().getImmutable();
			Element R0_ = ElementUtils.randomIn(pairing, gr);
			
			Element C_ = M.mul(Y.powZn(S));
			
			Element C0 = A0.powZn(S).mul(R0_);
			
			Element[][] s = new Element[universalAttrs.length][universalAttrs[0].length];
			Element[][] R = new Element[universalAttrs.length][universalAttrs[0].length];
			Element[][] C = new Element[universalAttrs.length][universalAttrs[0].length];
			for(int i = 0; i < universalAttrs.length; i++)
				for(int j = 0; j < universalAttrs[0].length; j++) {
					s[i][j] = pairing.getZr().newRandomElement().getImmutable();
					R[i][j] = ElementUtils.randomIn(pairing, gr);
					if(Utils.is_in_access_policy(accessPolicy, i, j))
						C[i][j] = A1.powZn(S).mul(R[i][j]);
					else
						C[i][j] = A1.powZn(s[i][j]).mul(R[i][j]);
				}
			timer[1] = System.nanoTime() - timer[1];
			System.out.println("################################### Encryption End ####################################");
			
			System.out.println("################################### KeyGen Begin ######################################");
			timer[2] = System.nanoTime();
			
			//�û������Լ���
			int[] userAttrs = ParametersUtils.user_attributes_satisfied_example_one_01;
			Element t = pairing.getZr().newZeroElement();
			
			//�����û������Լ��ϣ������û�����Կ
			Element[] ti = new Element[userAttrs.length];
			Element[] D = new Element[userAttrs.length];
			for(int i = 0; i < userAttrs.length; i++) {
				ti[i] = pairing.getZr().newRandomElement().getImmutable();
				D[i] = gp.powZn(ti[i].mul(a.invert()));
				t = t.add(ti[i]);
			}
			Element D0 = gp.powZn(omega.sub(t));
			timer[2] = System.nanoTime() - timer[2];
			System.out.println("################################### KeyGen End #########################################");
			
			System.out.println("################################### Decryption Begin ###################################");
			timer[3] = System.nanoTime();
			
			Element CD0 = pairing.pairing(C0, D0);
			Element CD = pairing.getGT().newOneElement();
			for(int i = 0; i < userAttrs.length; i++)
				CD = CD.mul(pairing.pairing(C[i][userAttrs[i]], D[i]));
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
				
				//����ʱ��ΪString���ͣ��Ա���д��Excel��
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
				System.out.println("Round "+ k +" decryption is not correct!\n");
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
