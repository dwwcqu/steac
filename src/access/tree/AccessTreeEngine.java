package access.tree;


import access.AccessControlEngine;
import access.AccessControlParameter;
import access.AccessTreeNode;
import access.UnsatisfiedAccessControlException;
import algebra.algorithms.LagrangePolynomial;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * This is the implementation of the access tree scheme proposed first proposed by Goyal, Pandey, Sahai, Waters in 2006.
 * Conference version: V. Goyal, O. Pandey, A. Sahai, B. Waters. Attribute-based encryption for fine-grained access control of encrypted data. CCS 2006, 89-98.
 * 访问树类型的访问控制机
 */
public class AccessTreeEngine implements AccessControlEngine {
    //一般访问树
	public static String SCHEME_NAME = "general access tree";
	
	//自定义一个instance实例
    private static AccessTreeEngine instance = new AccessTreeEngine();

    private AccessTreeEngine() {

    }

    public static AccessTreeEngine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
    
    //支持阈值门访问控制
    public boolean isSupportThresholdGate() {
        return true;
    }
    
    /*
     * 根据访问控制策略和一个属性集合，生成在在这个属性集合上的访问控制参数，即一颗完整的访问树结构
     */
    public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) {
        //init access tree
    	/*
    	 * 递归的进行整个访问树的构造，从根节点开始
    	 */
        AccessTreeNode accessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        //返回AccessControlParameter对象，即为一颗完整的访问控制树
        return new AccessControlParameter(accessTreeNode, accessPolicy, rhos);
    }

    /**
     * 根据配对参数，需要分享的秘密值和整个访问控制树，进行每个属性的秘密分享Map<String,Element>
     */
    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) {
        Map<String, Element> sharedElementsMap = new HashMap<String, Element>();
        access_tree_node_secret_sharing(pairing, secret, accessControlParameter.getRootAccessTreeNode(), sharedElementsMap);
//        Object[] keySet = sharedElementsMap.keySet().toArray();
//        for (Object keys : keySet) {
//            System.out.println(keys + " : " + sharedElementsMap.get(keys));
//        }
        return sharedElementsMap;
    }
    
    /*
     * 针对每个节点完成以这个节点为根节点的秘密值分享
     */
    private void access_tree_node_secret_sharing(Pairing pairing, Element rootSecret, AccessTreeNode accessTreeNode, Map<String, Element> sharingResult) {
        //如果为叶子节点，即结束整个秘密值分享过程，直接把秘密值分享给这一属性
    	if (accessTreeNode.isLeafNode()) {
            //leaf node, add root secret into the map
            sharingResult.put(accessTreeNode.getAttribute(), rootSecret.duplicate().getImmutable());
        } else {
        	/*
        	 * 若为非叶子节点，需要根据一个朗格朗日多项式（由这个节点的孩子节点数和阈值数确定度）完成对每个孩子节点的秘密值分享
        	 */
            //non-leaf nodes, share secrets to child nodes
            LagrangePolynomial lagrangePolynomial = new LagrangePolynomial(pairing, accessTreeNode.getT() - 1, rootSecret);
            for (int i = 0; i < accessTreeNode.getN(); i++) {
                Element sharedSecret = lagrangePolynomial.evaluate(pairing.getZr().newElement(i + 1));
                //递归的对这个节点的每个孩子节点完成秘密值分享，直到叶子节点
                access_tree_node_secret_sharing(pairing, sharedSecret, accessTreeNode.getChildNodeAt(i), sharingResult);
            }
        }
    }
    
    /**
     * 计算给定属性集合和访问控制参数，计算每个属性的拉格朗日系数
     */
    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter)
            throws UnsatisfiedAccessControlException {
        Map<String, String> collisionMap = new HashMap<String, String>();
        for (String attribute : attributes) {
            if (collisionMap.containsKey(attribute)) {
                throw new UnsatisfiedAccessControlException("Invalid attribute set, containing identical attribute: " + attribute);
            } else {
                collisionMap.put(attribute, attribute);
            }
        }
        SatisfiedAccessTreeNode satisfiedAccessTreeNode = SatisfiedAccessTreeNode.GetSatisfiedAccessTreeNode(pairing, accessControlParameter.getRootAccessTreeNode());
        return SatisfiedAccessTreeNode.CalCoefficient(satisfiedAccessTreeNode, attributes);
    }
    
    /**
     * 一个内部类
     * 这个SatisfiedAccessTreeNode代表的是满足访问树的一个结点
     * 代表的是以这个节点开始的树是否满足访问树
     */
    private static class SatisfiedAccessTreeNode {
        private final Pairing pairing;
        private final SatisfiedAccessTreeNode parentNode;//父节点
        private final SatisfiedAccessTreeNode[] childNodes;//所有的孩子节点
        private final int index;//节点下标

        private final int t;//阈值
        private final int n;//孩子节点个数
        private final boolean isLeafNode;//是否为叶子节点
        private final String attribute;//若为叶子节点，则代表了属性，保存属性值
        private int[] satisfiedIndex;//满足以这个节点开始的访问树的下标
        private boolean isSatisfied;//这个属性集合最终是否满足
        
        
        static SatisfiedAccessTreeNode GetSatisfiedAccessTreeNode(Pairing pairing, AccessTreeNode rootAccessTreeNode) {
            return new SatisfiedAccessTreeNode(pairing, null, 0, rootAccessTreeNode);
        }
        
        /**
         * 
         * @param rootSatisfiedAccessTreeNode
         * @param attributes
         * @return Map<String, Element>
         * @throws UnsatisfiedAccessControlException
         */
        static Map<String, Element> CalCoefficient(SatisfiedAccessTreeNode rootSatisfiedAccessTreeNode, String[] attributes) throws UnsatisfiedAccessControlException {
            if (!rootSatisfiedAccessTreeNode.isAccessControlSatisfied(attributes)) {
            	//给定属性集合不满足访问树
                throw new UnsatisfiedAccessControlException("Give attribute set does not satisfy access policy");
            } else {
            	//从根节点出发，指顶向下进行每个属性的拉格朗日系数的求解
                Map<String, Element> coefficientElementsMap = new HashMap<String, Element>();
                rootSatisfiedAccessTreeNode.calcCoefficients(coefficientElementsMap);
//                Object[] keySet = coefficientElementsMap.keySet().toArray();
//                for (Object keys : keySet) {
//                    System.out.println(keys + " : " + coefficientElementsMap.get(keys));
//                }
                return coefficientElementsMap;
            }
        }
        
        /**
         * 构造方法，
         * @param pairing
         * @param parentSatisfiedAccessTreeNode
         * @param index
         * @param accessTreeNode
         */
        private SatisfiedAccessTreeNode(Pairing pairing, final SatisfiedAccessTreeNode parentSatisfiedAccessTreeNode, int index, final AccessTreeNode accessTreeNode) {
            this.pairing = pairing;
            this.parentNode = parentSatisfiedAccessTreeNode;
            this.index = index;
            //若为叶子节点
            if (accessTreeNode.isLeafNode()) {
                this.childNodes = null;
                this.t = 1;
                this.n = 1;
                this.attribute = accessTreeNode.getAttribute();
                this.isLeafNode = true;
            } else {
            	//内部节点
                this.t = accessTreeNode.getT();
                this.n = accessTreeNode.getN();
                this.isLeafNode = false;
                this.attribute = null;
                this.childNodes = new SatisfiedAccessTreeNode[this.n];
                for (int i = 0; i < this.childNodes.length; i++) {
                    this.childNodes[i] = new SatisfiedAccessTreeNode(pairing, this, i + 1, accessTreeNode.getChildNodeAt(i));
//                    System.out.println("Node: " + this.childNodes[i].label + " with parentNode: " + this.label);
                }
            }
        }
        
        /**
         * 给定一个属性集合，判断这个属性集合是否满足以这个节点为根节点的访问树
         * @param attributes
         * @return
         */
        private boolean isAccessControlSatisfied(final String[] attributes) {
            this.isSatisfied = false;
            if (!this.isLeafNode) {
                int[] tempIndex = new int[this.childNodes.length];
                int satisfiedChildNumber = 0;
                for (int i = 0; i < this.childNodes.length; i++) {
                    if (childNodes[i].isAccessControlSatisfied(attributes)) {
                        tempIndex[i] = i + 1;
                        satisfiedChildNumber++;
                    }
                }
                this.satisfiedIndex = new int[satisfiedChildNumber];
                for (int i = 0, j = 0; i < this.childNodes.length; i++) {
                    if (tempIndex[i] > 0) {
                        this.satisfiedIndex[j] = tempIndex[i];
                        j++;
                    }
                }
//                System.out.println("Node " + this.label + " has satisfied child nodes " + satisfiedChildNumber);
                this.isSatisfied = (satisfiedChildNumber >= t);
            } else {
                for (String attribute1 : attributes) {
                    if (this.attribute.equals(attribute1)) {
                        this.isSatisfied = true;
                    }
                }
            }
            return this.isSatisfied;
        }
        
        /**
         * 
         * @param coefficientElementsMap
         */
        private void calcCoefficients(Map<String, Element> coefficientElementsMap) {
            
        	/*
        	 * 如果不为叶子节点且属性集合满足以这个节点开始访问树
        	 */
        	if (!this.isLeafNode && this.isSatisfied) {
                for (SatisfiedAccessTreeNode childNode : this.childNodes) {
                    if (childNode.isSatisfied) {
                    	//计算每个孩子节点的系数
                        childNode.calcCoefficients(coefficientElementsMap);
                    }
                }
            } else {
                if (!this.isSatisfied) {
                    return;//不满足访问结构
                }
                //满足访问结构，但是为叶子节点，根据这个节点的父节点返回这一节点的拉格朗日系数
                SatisfiedAccessTreeNode currentNode = this;
                Element coefficientElement =  pairing.getZr().newOneElement().getImmutable();
                while (currentNode.parentNode != null) {
                    int currentNodeIndex = currentNode.index;
                    currentNode = currentNode.parentNode;
                    coefficientElement = coefficientElement.mulZn(LagrangePolynomial.calCoef(pairing, currentNode.satisfiedIndex, currentNodeIndex)).getImmutable();
                }
                coefficientElementsMap.put(this.attribute, coefficientElement);
            }
        }
    }
}
