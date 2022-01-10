package utils;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Utilities for pairing-based cryptography.
 * 用于基于配对操作密码学算法所需要使用的一些使用接口方法
 */
public class PairingUtils {
	
	/**
	 * 配置双线性配对的代数结构所需要的一些配置参数
	 */
    public static final String PATH_a_160_512 = "params//a_160_512.properties";
//    public static final String PATH_a_320_512 = "params//a_320_512.properties";
//    public static final String PATH_a1_2_256 = "params//a1_2_256.properties";
//    public static final String PATH_a1_3_256 = "params//a1_3_256.properties";
//    public static final String PATH_a1_2_512 = "params//a1_2_512.properties";
    public static final String PATH_a1_3_512 = "params//a1_3_512.properties";
    public static final String PATH_f_160 = "params//f_160.properties";
    
    public enum PairingGroupType {
        Zr, G1, G2, GT,
    }

//    public static final PairingParameters DEFAULT_TYPE_A_160_512_PAIRING_PARAMETER = PairingFactory.getPairingParameters()

//    /**
//     * Generate type A parameter for further used in paiaring-based cryptography.
//     * @param rBitLength Bit length for the group Z_r
//     * @param qBitLength Bit length for the group G and G_T
//     * @return Type A pairing parameters
//     */
//    public static PropertiesParameters GenerateTypeAParameters(int rBitLength, int qBitLength) {
//        PropertiesParameters parameters;
//        Pairing pairing;
//        Element g;
//        // Generate curve parameters
//        while (true) {
//            parameters = generate_type_a_curve_params(rBitLength, qBitLength);
//            pairing = PairingFactory.getPairing(parameters);
//            g = pairing.getG1().newRandomElement().getImmutable();
//            if (!pairing.pairing(g, g).isOne()) { break; }
//        }
//        return parameters;
//    }

//    public static PropertiesParameters GenerateTypeA1Parameters(int qBitLength) {
//        PropertiesParameters parameters;
//        Pairing pairing;
//        Element generator;
//        Element g;
//
//        // Generate curve parameters
//        while (true) {
//            parameters = generate_type_a1_curve_params(qBitLength);
//            pairing = PairingFactory.getPairing(parameters);
//            generator = pairing.getG1().newRandomElement().getImmutable();
//            g = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
//            if (!pairing.pairing(g, g).isOne()) { break; }
//        }
//        return parameters;
//    }

//    private static PropertiesParameters generate_type_a_curve_params(int rBitLength, int qBitLength) {
//        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(rBitLength, qBitLength);
//        return (PropertiesParameters) parametersGenerator.generate();
//    }

//    private static PropertiesParameters generate_type_a1_curve_params(int qBitLength) {
//        PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(3, qBitLength);
//        return (PropertiesParameters) parametersGenerator.generate();
//    }

    /**
     * A standard collision resistant hash function implementations used privately for Map.
     * The used hash function is SHA-256.
     * @param message mmessage to be hashed
     * @return hash result
     * 对以字节数组形式保存的数据进行数字摘要，使用的SHA-256，同样以字节数组的形式返回摘要
     */
    private static byte[] hash(byte[] message) {
    	//使用java.security中的MessageDigest
    	MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            //Impossible to get this exception
            e.printStackTrace();
        }
        assert (md != null);
        md.update(message);
        return md.digest();
    }
    
    /**
     * 根据配对的参数和字节数组形式的数据，以及想要把这个数据映射到那个代数结构（Zr，G1，G2，GT）上
     * 最终返回这个消息映射到这个代数结构上的一个唯一元素
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return Element
     */
    public static Element MapByteArrayToGroup(Pairing pairing, byte[] message, PairingGroupType pairingGroupType) {
        byte[] shaResult = hash(message);
        switch (pairingGroupType) {
            case Zr: return pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case G1: return pairing.getG1().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case G2: return pairing.getG2().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            case GT: return pairing.getGT().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
            default: throw new RuntimeException("Invalid pairing group type.");
        }
    }
    
    /**
     * 把一个String类型的数据映射到一个给定代数结构上的某一个元素上
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return
     */
    public static Element MapStringToGroup(Pairing pairing, String message, PairingGroupType pairingGroupType) {
        return PairingUtils.MapByteArrayToGroup(pairing, message.getBytes(), pairingGroupType);
    }
    
    public static Element MapByteArrayToFirstHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(message);
        byte[] hashZr = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
        hashZr[0] &= 0xEF;
        return pairing.getZr().newElementFromBytes(hashZr).getImmutable();
    }

    public static Element MapByteArrayToSecondHalfZr(Pairing pairing, byte[] message) {
        byte[] shaResult = hash(message);
        byte[] hash = pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).toBytes();
        hash[0] |= 0x80;
        return pairing.getZr().newElementFromBytes(hash).getImmutable();
    }
    
    /**
     * 把一个String数组的每个String映射到一个代数结构上，并返回每个String在代数结构上的元素
     * @param pairing
     * @param message
     * @param pairingGroupType
     * @return
     */
    public static Element[] MapStringArrayToGroup(Pairing pairing, String[] message, PairingGroupType pairingGroupType){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            if (message[i] == null) {
                continue;
            }
            elements[i] = PairingUtils.MapByteArrayToGroup(pairing, message[i].getBytes(), pairingGroupType);
        }
        return elements;
    }
    
    
    /**
     * 
     * @param pairing
     * @param message
     * @return
     */
    public static Element[] MapStringArrayToFirstHalfZr(Pairing pairing, String[] message){
        Element[] elements = new Element[message.length];
        for (int i = 0; i < elements.length; i++) {
            elements[i] = PairingUtils.MapByteArrayToFirstHalfZr(pairing, message[i].getBytes());
        }
        return elements;
    }
    
    /**
     * 给定某一个代数结构上的一个元素数组，将其映射到一个String数组上
     * @param message
     * @return String[]
     */
    public static String[] MapElementArrayToStringArray(Element[] message) {
        String[] strings = new String[message.length];
        for (int i = 0; i < message.length; i++) {
            strings[i] = message[i].toString();
        }
        return strings;
    }
    
    /**
     * 给定某代数结构上的两个元素，判断两个是否为同一个元素
     * @param thisElement
     * @param thatElement
     * @return boolean
     */
    public static boolean isEqualElement(final Element thisElement, final Element thatElement) {
        if (thisElement == null && thatElement != null) {
            return false;
        }
        if (thisElement != null && thatElement == null) {
            return false;
        }
        if (thisElement == thatElement) {
            return true;
        }
        String stringThisElement = new String(Hex.encode(thisElement.toBytes()));
        String stringThatElement = new String(Hex.encode(thatElement.toBytes()));
        return (stringThisElement.equals(stringThatElement));
    }
    
    /**
     * 给定某个代数结构上的两个元素数组，判断这个两个元素数组是否相同
     * @param thisElementArray
     * @param thatElementArray
     * @return boolean
     */
    public static boolean isEqualElementArray(final Element[] thisElementArray, final Element[] thatElementArray) {
        if (thisElementArray == thatElementArray) {
            return true;
        }
        if (thisElementArray.length != thatElementArray.length) {
            return false;
        }
        for (int i=0; i<thisElementArray.length; i++){
            if (!(PairingUtils.isEqualElement(thisElementArray[i], thatElementArray[i]))){
                return false;
            }
        }
        return true;
    }
    
    
    /**
     * 判断两个二维字节数组是否相同
     * @param thisByteArrays
     * @param thatByteArrays
     * @return boolean
     */
    public static boolean isEqualByteArrays(final byte[][] thisByteArrays, final byte[][] thatByteArrays) {
        if (thisByteArrays == thatByteArrays) {
            return true;
        }
        if (thisByteArrays.length != thatByteArrays.length) {
            return false;
        }
        for (int i=0; i<thisByteArrays.length; i++){
            if (!(Arrays.equals(thisByteArrays[i], thatByteArrays[i]))){
                return false;
            }
        }
        return true;
    }
    
    /**
     * 判断两个String到byte[]映射map是否相同
     * @param thisMap
     * @param thatMap
     * @return boolean
     */
    public static boolean isEqualByteArrayMaps(final Map<String, byte[]> thisMap, final Map<String, byte[]> thatMap) {
        if (thisMap == thatMap) {
            return true;
        }
        for (String thisString : thisMap.keySet()) {
            if (!Arrays.equals(thisMap.get(thisString), thatMap.get(thisString))) {
                return false;
            }
        }
        for (String thatString : thatMap.keySet()) {
            if (!Arrays.equals(thisMap.get(thatString), thatMap.get(thatString))) {
                return false;
            }
        }
        return true;
    }
    
    
    /**
     * 把某个代数结构上的元素数组映射到一个二维字节数组上
     * @param elementArray
     * @return byte[][]
     */
    public static byte[][] GetElementArrayBytes(Element[] elementArray) {
        byte[][] byteArrays = new byte[elementArray.length][];
        for (int i = 0; i < byteArrays.length; i++) {
            if (elementArray[i] == null) {
                byteArrays[i] = null;
                continue;
            }
            byteArrays[i] = elementArray[i].toBytes();
        }
        return byteArrays;
    }

   /*
    * 根据给定的代数结构，把二维数组中每行元素映射到一个代数结构上的某一个唯一元素，并返回这个元素数组
    */
    public static Element[] GetElementArrayFromBytes(Pairing pairing, byte[][] byteArrays, PairingGroupType groupType) {
        Element[] elementArray = new Element[byteArrays.length];
        for (int i = 0; i < elementArray.length; i++) {
            if (byteArrays[i] == null) {
                elementArray[i] = null;
                continue;
            }
            switch (groupType) {
                case Zr: elementArray[i] = pairing.getZr().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case G1: elementArray[i] = pairing.getG1().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case G2: elementArray[i] = pairing.getG2().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                case GT: elementArray[i] = pairing.getGT().newElementFromBytes(byteArrays[i]).getImmutable();
                    break;
                default:
                    throw new RuntimeException("Invalid pairing group type.");
            }
        }
        return elementArray;
    }
    
    //移除String[]中重复的字符串，并返回String[]
    public static String[] removeDuplicates(String[] orginalArray) {
        Set<String> stringSet = new HashSet<String>();
        Collections.addAll(stringSet, orginalArray);
        return stringSet.toArray(new String[1]);
    }
    
    /*
     * 移除int[]中重复的数字，并返回int[]
     */
    public static int[] removeDuplicates(int[] originalArray) {
        Set<Integer> intSet = new HashSet<Integer>();
        for (int i : originalArray) {
            intSet.add(i);
        }
        int[] resultSet = new int[intSet.size()];
        int label = 0;
        for (Integer setInteger : intSet) {
            resultSet[label] = setInteger;
            label++;
        }
        return resultSet;
    }
    
    /*
     * 对给定的CipherParameter进行序列化，并以字节数组的形式返回序列化的结果
     */
    public static byte[] SerCipherParameter(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(cipherParameters);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();
        return byteArray;
    }
    
    /*
     * 反序列化，给定一个字节数组，把其反序列化成一个CipherParameters对象并返回
     */
    public static CipherParameters deserCipherParameters(byte[] byteArrays) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrays);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        CipherParameters cipherParameters = (CipherParameters)objectInputStream.readObject();
        objectInputStream.close();
        byteArrayInputStream.close();
        return cipherParameters;
    }

    public static void NotVerifyCipherParameterInstance(String schemeName, Object parameters,
                                                     String className) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + schemeName  + ", find "
                            + parameters.getClass().getName() + ", require"
                            + className);
    }
}
