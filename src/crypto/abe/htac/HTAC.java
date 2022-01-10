package crypto.abe.htac;

import java.io.FileOutputStream;
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
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import jxl.Workbook;
import jxl.write.Label;
import jxl.write.WritableSheet;
import jxl.write.WritableWorkbook;

public class HTAC {
	public static void main(String[] args) throws Exception {
		FileOutputStream os = new FileOutputStream("src//crypto//abe//htac//performance01.xls");
		//创建Excel工作薄
		WritableWorkbook file = Workbook.createWorkbook(os);
		//创建工作薄上面的一个工作表
		WritableSheet ws = file.createSheet("HATC", 0);
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
		PropertiesParameters propertiesP = new PropertiesParameters().load("params//a1_4_128.properties");
		Pairing pairing = PairingFactory.getPairing(propertiesP);
		
		for(int rd = 1; rd <= 20; ++rd) {
			
			for(int hard = 0; hard < 5; ++hard) {
				AccessPolicyParser app = new AccessPolicyParser(ABEParam.getAt(rd)[hard]);
				LSSSParameters lp = app.accessParser();//保存访问策略参数
				Vector<String> uAttrs = lp.getAttrs();//整个系统的全局属性集合
				long[] timer = {0,0,0,0,0};
				for(int avg = 1; avg <= 20; ++avg) {
					long nowt = 0;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Setup Begin ----------");
					nowt = System.nanoTime();
					Element generator = pairing.getG1().newRandomElement().getImmutable();
					Element g1 = ElementUtils.getGenerator(pairing, generator, propertiesP, 0, 4).getImmutable();
					Element g3 = ElementUtils.getGenerator(pairing, generator, propertiesP, 2, 4).getImmutable();
					Element g4 = ElementUtils.getGenerator(pairing, generator, propertiesP, 3, 4).getImmutable();
					Element alpha = pairing.getZr().newRandomElement().getImmutable();//alpha
					Element a = pairing.getZr().newRandomElement().getImmutable();//a
					Element b = pairing.getZr().newRandomElement().getImmutable();//b
					Element g = ElementUtils.randomIn(pairing, g1).getImmutable();//g
					Element ga = g.powZn(a).getImmutable();//ga = g^a
					Element gb = g.powZn(b).getImmutable();//gb = g^b
					Element h = ElementUtils.randomIn(pairing, g1).getImmutable();//h
					Element X3 = ElementUtils.randomIn(pairing, g3).getImmutable();//X3
					Element Z = ElementUtils.randomIn(pairing, g4).getImmutable();//Z
					Element X4 = ElementUtils.randomIn(pairing, g4).getImmutable();//X4
					Element Y = pairing.pairing(g, g).powZn(alpha).getImmutable();//Y = e(g,g)^alpha
					Element H = h.mul(Z).getImmutable();//H = hZ
					Map<String,Element> N = new HashMap<String, Element>();
					for(String attr:uAttrs)
						N.put(attr, pairing.getZr().newRandomElement().getImmutable());//N
					timer[0] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Setup End ----------");
					//找到用户的属性集合
					int childAttr = (hard + 1) * (5 * rd);
					childAttr *= 0.2;
					String[] userAttr = new String[childAttr];
					for(int i = 0; i < childAttr; ++i)
						userAttr[i] = uAttrs.get(i);//这个就是用户的属性集合
					//密钥生成开始
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" KeyGen Begin ----------");
					nowt = System.nanoTime();
					Element c = pairing.getZr().newRandomElement();//c
					Element t = pairing.getZr().newRandomElement();//t
					Element R = ElementUtils.randomIn(pairing, g3);//R
					Element R_ = ElementUtils.randomIn(pairing, g3);//R'
					Element R__ = ElementUtils.randomIn(pairing, g3);//R''
					//K = g ^ (alpha/(b + c)) * g ^ at * R
					Element K = g.powZn(alpha.div(b.add(c))).mul(ga.powZn(t)).mul(R).getImmutable();
					Element K_ = g.powZn(t).mul(R_).getImmutable();//K' = g^t * R'
					Element L = c.duplicate().getImmutable();//L = c
					Element L_ = gb.powZn(t).mul(R__).getImmutable();//L' = g ^ bt * R''
					//Ki = (g ^ Ni * h) ^ ((b+c)*t) * Ri
					Map<String,Element> Ki = new HashMap<String, Element>();
					for(String attr:userAttr) {
						Element Ri = ElementUtils.randomIn(pairing, g3);
						Ki.put(attr, g.powZn(N.get(attr)).mul(h).powZn(b.add(c).mul(t)).mul(Ri).getImmutable());
					}
					timer[1] += System.nanoTime() - nowt;
					//密钥生成结束
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" KeyGen End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Encrypt Begin ----------");
					nowt = System.nanoTime();
					Element m = pairing.getGT().newRandomElement().getImmutable();//被加密数据
					ZrMatrix M = new ZrMatrix(lp,pairing);
					ZrVector V = new ZrVector(M.getColnum(), pairing, Cate.Random);
					ZrVector U = new ZrVector(M.getColnum(), pairing, Cate.Random);
					
					ZrVector lambda = M.multi(V);
					ZrVector gama = M.multi(U);
					Element Q  = ElementUtils.randomIn(pairing, g4);//Q
					Element Q1 = ElementUtils.randomIn(pairing, g4);//Q1
					
					Element Ct = Y.powZn(U.getAt(0)).getImmutable();//Ct = Y^ s'
					Element Ctt = g.powZn(U.getAt(0)).mul(Q).getImmutable();//Ctt = g^s' * Q
					Element Cttt = gb.powZn(U.getAt(0)).mul(Q1).getImmutable();//Cttt = g ^ (b*s') * Q1
					
					Element C = m.mul(Y.powZn(V.getAt(0))).getImmutable();//C = m * Y^s
					Element CC = g.powZn(V.getAt(0)).getImmutable();//CC = g^s
					Element CCC = gb.powZn(V.getAt(0)).getImmutable();//CCC = g ^ (b*s)
					
					//Cti = ga^gamai * (g^Ni * H) ^ (-s') * Zcti
					Map<String,Element> Cti = new HashMap<String, Element>();
					//Ci = ga ^ lambadai * (g^Ni * H) ^ (-ri) * Zci
					Map<String,Element> Ci = new HashMap<String, Element>();
					//Di = g ^ ri * Zdi
					Map<String,Element> Di = new HashMap<String, Element>();
					for(int i = 0; i < uAttrs.size(); ++i) {
						Element ri = pairing.getZr().newRandomElement();
						Element Zcti = ElementUtils.randomIn(pairing, g4);
						Element Zci = ElementUtils.randomIn(pairing, g4);
						Element Zdi = ElementUtils.randomIn(pairing, g4);
						Element s_ = U.getAt(0).duplicate();
						Element temp1 = g.powZn(N.get(uAttrs.get(i))).mul(H).powZn(s_.negate());
						Cti.put(uAttrs.get(i),ga.powZn(gama.getAt(i)).mul(temp1).mul(Zcti).getImmutable());
						Di.put(uAttrs.get(i), g.powZn(ri).mul(Zdi).getImmutable());
						Element temp2 = g.powZn(N.get(uAttrs.get(i))).mul(H).powZn(ri.negate());
						Ci.put(uAttrs.get(i), ga.powZn(lambda.getAt(i)).mul(temp2).mul(Zci).getImmutable());
					}
					timer[2] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Encrypt End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Test Begin ----------");
					nowt = System.nanoTime();
					ZrMatrix subM = M.subMatrix(userAttr);
					String[] userattinpolicy = subM.getAttrs();
					ZrMatrix transubm = subM.trans();
					ZrVector bb = new ZrVector(transubm.getRownum(),pairing,Cate.Special);
					ZrVector so = transubm.slove(bb);
			
					int k = 0;
					Element temp1 = K_.powZn(L).mul(L_);
					Element temp2 = Ctt.powZn(L).mul(Cttt);
					Element total = pairing.getGT().newOneElement();
					for(String attr:userattinpolicy) {
						Element e1 = pairing.pairing(Cti.get(attr), temp1);
						Element e2 = pairing.pairing(Ctt,Ki.get(attr));
						total = total.mul(e1.mul(e2).powZn(so.getAt(k)));
						++k;
					}
					Element e3 = pairing.pairing(temp2, K.invert());
					Element Ct_ = total.mul(e3);
					if(!Ct.invert().isEqual(Ct_)) {
						file.write();
						file.close();
						throw new Exception("Round " + rd + ",Hardness " + hard +" Decryt test fail");
					}
					timer[3] += System.nanoTime() - nowt;
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Test End ----------");
					
					System.out.println("---------- Round "+ rd +",Hardness "+ hard +" Decrypt Begin ----------");
					nowt = System.nanoTime();
					Element numerator = pairing.pairing(CC.powZn(L).mul(CCC),K);//e(CC,K)
					Element denominator = pairing.getGT().newOneElement();//
					int j = 0;
					for(String att: userattinpolicy) {
						Element CiL = pairing.pairing(Ci.get(att), K_.powZn(L).mul(L_));//e(Ci,K'^L * L')
						Element DiKx = pairing.pairing(Di.get(att),Ki.get(att));//e(Di,Ki)
						denominator = denominator.mul(CiL.mul(DiKx).powZn(so.getAt(j)));
						++j;
					}
					Element m_ = C.div(numerator.div(denominator));
					if(!m.isEqual(m_)) {
						file.write();
						file.close();
						throw new Exception("Round " + rd + ",Hardness " + hard +" Decryt fail");
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
						double hardness = ((double)(hard + 1)) * 0.2;
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
