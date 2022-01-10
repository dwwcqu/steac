package crypto.abe;

import java.util.Vector;

public class ABEParam {
	
	public static final String[] access_policy_5 = {
			"(A,B,C,D,E,1)",
			"(A,B,C,D,E,2)",
			"(A,B,C,D,E,3)",
			"(A,B,C,D,E,4)",
			"(A,B,C,D,E,5)"
	};
	
	public static final String[] access_policy_10 = {
			"(A,B,C,D,E,F,G,H,I,J,2)",
			"(A,B,C,D,E,F,G,H,I,J,4)",
			"(A,B,C,D,E,F,G,H,I,J,6)",
			"(A,B,C,D,E,F,G,H,I,J,8)",
			"(A,B,C,D,E,F,G,H,I,J,10)"
	};
	
	public static final String[] access_policy_15 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,3)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,6)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,9)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,12)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,15)"
	};
	
	public static final String[] access_policy_20 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,4)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,8)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,12)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,16)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,20)"
	};
	
	public static final String[] access_policy_25 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,5)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,10)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,15)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,20)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,25)"
	};
	
	public static final String[] access_policy_30 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Aa,Ba,Ca,Da,Ea,6)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Aa,Ba,Ca,Da,Ea,12)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Aa,Ba,Ca,Da,Ea,18)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Aa,Ba,Ca,Da,Ea,24)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Aa,Ba,Ca,Da,Ea,30)"
	};
	
	public static final String[] access_policy_35 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,7)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,14)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,21)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,28)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,35)"
	};
	
	public static final String[] access_policy_40 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,8)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,16)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,24)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,32)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
			+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,40)"
	};
	
	public static final String[] access_policy_45 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,9)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,18)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,27)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,36)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,45)"
	};
	
	public static final String[] access_policy_50 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,10)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,20)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,30)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,40)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,50)"
	};
	
	public static final String[] access_policy_55 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,11)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,22)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,33)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,44)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,55)"
	};
	
	public static final String[] access_policy_60 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,12)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,24)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,36)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,48)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,60)"
	};
	
	public static final String[] access_policy_65 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,13)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,26)",	
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,39)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,52)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,65)"
	};
	
	public static final String[] access_policy_70 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,14)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,28)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,42)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,56)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,70)"
	};
	
	public static final String[] access_policy_75 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,15)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,30)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,45)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,60)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,75)"
	};
	
	public static final String[] access_policy_80 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,16)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,32)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,48)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,64)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,80)"									
	};
	
	public static final String[] access_policy_85 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,17)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,34)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,51)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,68)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,85)"
	};
	
	public static final String[] access_policy_90 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,18)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,36)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,54)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,72)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,90)"
	};
	
	public static final String[] access_policy_95 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,19)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,38)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,57)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,76)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,95)"
	};
	
	public static final String[] access_policy_100 = {
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,Uc,Vc,Wc,Xc,Yc,20)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,Uc,Vc,Wc,Xc,Yc,40)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,Uc,Vc,Wc,Xc,Yc,60)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,Uc,Vc,Wc,Xc,Yc,80)",
			"(A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,"
					+ "Aa,Ba,Ca,Da,Ea,Fa,Ga,Ha,Ia,Ja,Ka,La,Ma,Na,Oa,Pa,Qa,Ra,Sa,Ta,Ua,Va,Wa,Xa,Ya,"
					+ "Ab,Bb,Cb,Db,Eb,Fb,Gb,Hb,Ib,Jb,Kb,Lb,Mb,Nb,Ob,Pb,Qb,Rb,Sb,Tb,Ub,Vb,Wb,Xb,Yb,"
					+ "Ac,Bc,Cc,Dc,Ec,Fc,Gc,Hc,Ic,Jc,Kc,Lc,Mc,Nc,Oc,Pc,Qc,Rc,Sc,Tc,Uc,Vc,Wc,Xc,Yc,100)",
	};
	
	public static String[] getAt(int index) throws Exception{
		int policy = index * 5;
		switch(index) {
		case 1: 
			return access_policy_5;
		case 2:
			return access_policy_10;
		case 3: 
			return access_policy_15;
		case 4:
			return access_policy_20;
		case 5: 
			return access_policy_25;
		case 6:
			return access_policy_30;
		case 7: 
			return access_policy_35;
		case 8:
			return access_policy_40;
		case 9: 
			return access_policy_45;
		case 10:
			return access_policy_50;
		case 11: 
			return access_policy_55;
		case 12:
			return access_policy_60;
		case 13:
			return access_policy_65;
		case 14: 
			return access_policy_70;
		case 15:
			return access_policy_75;
		case 16: 
			return access_policy_80;
		case 17:
			return access_policy_85;
		case 18: 
			return access_policy_90;
		case 19:
			return access_policy_95;
		case 20: 
			return access_policy_100;
		default:
			throw new Exception("access_policy_"+ policy +" doesn't exist!");
		}
	}
}
