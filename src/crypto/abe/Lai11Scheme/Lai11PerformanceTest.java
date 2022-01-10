package crypto.abe.Lai11Scheme;

import java.io.FileOutputStream;

import crypto.abe.UniversalAttributes;
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


public class Lai11PerformanceTest {
	
	
	public static void main(String[] args) throws Exception {
		
		FileOutputStream os = new FileOutputStream("src//crypto//abe//Performance//Lai11//performance.xls");
		//����Excel������
		WritableWorkbook file1 = Workbook.createWorkbook(os);
		//���������������һ��������
		WritableSheet ws = file1.createSheet("Lai11Scheme", 0);
		
		String[] titles = {
							"Attributes Number","SetUp Time",
							"KeyGen Time","Encryption Time",
				           "Decryption Time","ToTal Time"
				           };
		for(int i = 0; i < titles.length;i++) {
			Label lable = new Label(i, 0, titles[i]);
			ws.addCell(lable);
		}
		
		for(int k = 1; k <= 10; k++) {
			
			UniversalAttributes ua = new UniversalAttributes(k);
			int[][] universalAttrs = ua.getUniersalAttributes();
			int[][] accessPolicy = ua.getAccessPolicy();
			int[] userAttrs = ua.getSatisfiedAttributes(accessPolicy);
			
			long[] timer = new long[4];
			System.out.println("################################### Setup Begin ########################################");
			timer[0] = System.nanoTime();
			//ϵͳ��ȫ�����Ա�ʾ
			//int[][] universalAttrs = Utils.universal_attributes_example_one;
			//����ϵͳ����Դ����ṹ
			PropertiesParameters propertiesP = new PropertiesParameters().load("params//a1_3_128.properties");
			Pairing pairing = PairingFactory.getPairing(propertiesP);
			
			//GȺ���������Ԫ
			Element generator = pairing.getG1().newRandomElement().getImmutable();
			
			//Gp��Ⱥ���������Ԫgp
			Element gp = ElementUtils.getGenerator(pairing, generator, propertiesP, 0, 3);
			
			//Gr��Ⱥ���������Ԫgr
			Element gr = ElementUtils.getGenerator(pairing, generator, propertiesP, 1, 3);
			
			//ϵͳ������Կ
			Element[][] a = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//Rij ΪȺGr�ϵ�Ԫ��
			Element[][] R = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//ϵͳ�������� Aij = gp^aij * Rij����ÿ�����Ե�ÿ������ֵ��������һ����������
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
			
			//�û������Լ��ϣ���һ��һά�����ʾ��ÿ������ֵ������ÿ�������Ե������±�
			//int[] userAttrs = Utils.user_attributes_satisfied_example_one_01;
			
			//Di�����û���ÿ�����ԣ�ϵͳ��������һ��Կ��
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
			 * ���ܽ׶�ʹ�õķ��ʲ��ԣ��ö�ά�����ʾ��
			 * �кŴ������������±꣬�д����������Ը���������������
			 * ���������ֵΪû�����Ե�����ֵ�ڵ�ǰ���������±�
			 */
			//int[][] accessPolicy = Utils.access_policy_example_one;
			
			//GTȺ�ϵ����Ԫ�ش������ܵ�����M
			Element M = pairing.getGT().newRandomElement().getImmutable();
			
			//s�����ܽ׶����ѡȡ��һ��Zr�ϵ�Ԫ��
			Element S = pairing.getZr().newRandomElement().getImmutable();
			
			//R0'
			Element R0_ = ElementUtils.randomIn(pairing, gr);
			
			//sij
			Element[][] s = new Element[universalAttrs.length][universalAttrs[0].length];
			
			//Rij'
			Element[][] R_ = new Element[universalAttrs.length][universalAttrs[0].length];
			
			/*
			 * ���ÿ���������ÿ������ֵ
			 * ��������ֵλ�ڷ��ʿ��Ʋ����У���Cij = Aij ^ s * Rij'
			 * ����Cij = Aij ^ sij * Rij'
			 */
			Element[][] C = new Element[universalAttrs.length][universalAttrs[0].length];
			for(int i = 0; i < universalAttrs.length; i++)
				for(int j = 0; j < universalAttrs[0].length; j++) {
					s[i][j] = pairing.getZr().newRandomElement().getImmutable();
					R_[i][j] = ElementUtils.randomIn(pairing, gr);
					if(Utils.is_in_access_policy(accessPolicy, i, j))
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
			
			//Pai[e(Ciji,Di)]�������ݽ��շ���ÿ������ֵ���������±��ʾ���Լ���Ӧ��Կ�ף���ԭ����Կ����׶�����ֵ
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
				}
				//����ʱ��ΪString���ͣ��Ա���д��Excel��
				String[] timeRecords = new String[5];
				for(int i = 0; i < timer.length; i++)
					timeRecords[i] = String.valueOf((double)timer[i] / 1000000000L);
				timeRecords[4] = String.valueOf(totalTime);
				
				Label index = new Label(0,k,String.valueOf(k*k));
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
		file1.write();
		file1.close();
			
	}
}
