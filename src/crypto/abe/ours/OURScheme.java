package crypto.abe.ours;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import crypto.abe.ABEParam;
import crypto.abe.AccessPolicyParser;
import crypto.abe.LSSSParameters;
import crypto.abe.lsss.Cate;
import crypto.abe.lsss.ZrMatrix;
import crypto.abe.lsss.ZrVector;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;



public class OURScheme {
	
	public static void main(String[] args) throws Exception {
		FileOutputStream os = new FileOutputStream("src//crypto//abe//ours//performance02.xls");
		//创建Excel工作薄
		WritableWorkbook file = Workbook.createWorkbook(os);
		//创建工作薄上面的一个工作表
		WritableSheet ws = file.createSheet("Ours", 0);
		String[] titles = {
				"Attributes Number in Access Policy",
				"Diffculty Degree",
				"SetUp Time",
				"KeyGen Time",
				"Encryption Time",
				"Decryption Test Time",
				"Decryption Time"
	           };
		for(int i = 0; i < titles.length;i++) {
			Label lable = new Label(i, 0, titles[i]);
			ws.addCell(lable);
		}
		Pairing pairing = PairingFactory.getPairing("params//a1_2_128.properties");
		
		for(int rd = 1; rd <= 20; ++rd) {
			
			for(int hard = 0; hard < 5; ++hard) {
				AccessPolicyParser app = new AccessPolicyParser(ABEParam.getAt(rd)[hard]);
				LSSSParameters lp = app.accessParser();
				Vector<String> uAttrs = lp.getAttrs();
				long[] timer = {0,0,0,0,0};
				for(int avg = 1; avg <= 20; ++avg) {
					long nowt = 0;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Setup Begin ----------");
					nowt = System.nanoTime();
					Element generator = pairing.getG1().newRandomElement().getImmutable();
					Element alpha = pairing.getZr().newRandomElement().getImmutable();
					Element a = pairing.getZr().newRandomElement().getImmutable();
					
					Element omega = pairing.pairing(generator, generator).powZn(alpha).getImmutable();
					Element ga = generator.powZn(a);
					
					Map<String,Element> hi = new HashMap<String, Element>();
					for(String att:uAttrs) 
						hi.put(att, pairing.getG1().newRandomElement().getImmutable());
					Element msk = generator.powZn(alpha);
					timer[0] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Setup End ----------");
					
					int childAttr = (hard + 1) * (5 * rd);
					childAttr *= 0.2;
					String[] userAttr = new String[childAttr];
					for(int i = 0; i < childAttr; ++i)
						userAttr[i] = uAttrs.get(i);
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" KeyGen Begin ----------");
					nowt = System.nanoTime();
					Element t = pairing.getZr().newRandomElement().getImmutable();
					Element K = msk.mul(ga.powZn(t));
					Element L = generator.powZn(t);
					Map<String,Element> Kx = new HashMap<String, Element>();
					for(String att:userAttr)
						Kx.put(att, hi.get(att).powZn(t));
					timer[1] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" KeyGen End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Encrypt Begin ----------");
					nowt = System.nanoTime();
					Element m = pairing.getGT().newRandomElement().getImmutable();
					ZrMatrix M = new ZrMatrix(lp,pairing);
					ZrVector V = new ZrVector(M.getColnum(), pairing, Cate.Random);
					ZrVector U = new ZrVector(M.getColnum(), pairing, Cate.Random);
					
					ZrVector lambda = M.multi(V);
					ZrVector gama = M.multi(U);
					
					Element C = m.mul(omega.powZn(V.getAt(0)));
					Element C_ = generator.powZn(V.getAt(0));
					Element Ct = omega.powZn(U.getAt(0));
					Element Ctt = generator.powZn(U.getAt(0));
					Map<String,Element> Ci = new HashMap<String, Element>();
					Map<String,Element> Di = new HashMap<String, Element>();
					Map<String,Element> Cti = new HashMap<String, Element>();
					for(int i = 0; i < uAttrs.size(); ++i) {
						Element ri = pairing.getZr().newRandomElement();
						Di.put(uAttrs.get(i),generator.powZn(ri));
						Ci.put(uAttrs.get(i), 
								ga.powZn(lambda.getAt(i))
								.mul(hi.get(M.rho(i)).powZn(ri.negate())));
						Cti.put(uAttrs.get(i), ga.powZn(gama.getAt(i)));
					}
					timer[2] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Encrypt End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Test Begin ----------");
					nowt = System.nanoTime();
					ZrMatrix subM = M.subMatrix(userAttr);
					String[] userattinpolicy = subM.getAttrs();
					ZrMatrix transubm = subM.trans();
					ZrVector b = new ZrVector(transubm.getRownum(),pairing,Cate.Special);
					ZrVector so = transubm.slove(b);
					Element D = pairing.getGT().newOneElement();
					Element A = pairing.pairing(K, Ctt);
					int i = 0;
					for(String att:userattinpolicy) {
						D = D.mul(pairing.pairing(Cti.get(att),L).powZn(so.getAt(i)));
						++i;
					}
					if(!Ct.isEqual(A.div(D))) {
						file.write();
						file.close();
						throw new Exception("Round " + rd + ",Hardness " + hard +" Decryt test fail");
					}
					timer[3] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Test End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Begin ----------");
					nowt = System.nanoTime();
					Element numerator = pairing.pairing(C_,K);
					Element denominator = pairing.getGT().newOneElement();
					int j = 0;
					for(String att: userattinpolicy) {
						Element CiL = pairing.pairing(Ci.get(att), L);
						Element DiKx = pairing.pairing(Di.get(att),Kx.get(att));
						denominator = denominator.mul(CiL.mul(DiKx).powZn(so.getAt(j)));
						++j;
					}
					Element m_ = C.div(numerator.div(denominator));
					if(!m.isEqual(m_)) {
						file.write();
						file.close();
						throw new Exception("Round " + rd + ",Hardness " + hard +"Decryt fail");
					}
					timer[4] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt End ----------");
					
				}
				
				double[] avgtime = new double[5];
				for(int ii = 0; ii < 5; ++ii) {
					avgtime[ii] = (double)timer[ii] / 1000000000L;
					avgtime[ii] /= 20;
				}
				
				int newrownum = ws.getRows();
				int newcolnum = ws.getColumns();
				for(int jj = 0; jj < newcolnum; ++jj) {
					if(jj == 0) {
						int attrnum = 5 * rd;
						Label c1 = new Label(jj,newrownum,String.valueOf(attrnum));
						ws.addCell(c1);
					}
					else if(jj == 1) {
						double hardness = (double)(hard + 1) * 0.2;
						Label c2 = new Label(jj,newrownum,String.valueOf(hardness));
						ws.addCell(c2);
					}
					else {
						Label cc = new Label(jj,newrownum,String.valueOf(avgtime[jj - 2]));
						ws.addCell(cc);
					}
				}
			}
		}
		file.write();
		file.close();
		System.out.println("Success!");
	}
}
