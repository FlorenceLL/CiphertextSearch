import java.math.BigInteger;

import java.util.Random;

/**
* �����࣬������ʾ���Ķ�Ԫ��
*/

class Ciphertext {
    public BigInteger C1 = new BigInteger("0");
    public BigInteger C2 = new BigInteger("0");

    public void printCipher() {
        System.out.println("C1=" + C1);
        System.out.println("C2=" + C2);
    }
}

/**
 * ˫����̬ͬ�ӽ����㷨��Paillier cryptosystem with threshold decryption)
 * 
 * ��Կ���ɣ�
 * 1��ѡ������������p��q
 * 2������ n = pq�� lambda= lcm (p - 1,q-1)
 * 3��ѡ���������a����Z*_n^2,������Ԫg=-a^2n mod n^2
 * 4��ϵͳ��������Ϊ��N��g��
 * 5��ϵͳ˽ԿΪlambda��ϵͳ����˽ԿΪlambda1,lambda2
 * 6���û�˽ԿΪsk
 * 7���û���ԿΪpk=g^sk mod n^2
 * 
 * ����:
 * ѡ�������r
 * ��������C=(C1,C2)  C1=pk^r(1+mN)  C2=g^r mod n^2
 * ����mΪ����
 * 
 * �û����ܣ�
 * m=L(C1/C2^sk mod n^2)
 * 
 * ϵͳ���ܣ�
 * m = L(C1^lambda mod n^2)* lambda.modInverse(n) mod n
 * 
 * ϵͳ�ֲ����ܣ�
 * step1:C11=C1^lambda1 mod n^2
 * step2:C12=C11^lambda2 mod n^2
 *       m=L(C11,C12)
 * 
 * ����L(u) = (u-1)/n;
 */

public class PCTD{
	
	//p,q��������������� ;lambda = lcm(p-1, q-1)
    private static BigInteger p,q,lambda;
    
    //lambda0=modInverse(lambda);lambda1,lambda2Ϊ�ֽ��Ĳ���˽Կ
    private static BigInteger lambda0,lambda1,lambda2;
    
    //n=p*q
    public static BigInteger n;
    
    //nsquare=n*n
    public static BigInteger nsquare;
    
    //gΪ����Ԫ
    public static BigInteger g;
    
    //�û�˽Կ
    private  BigInteger sk;
    
    //�û���Կ
    public BigInteger pk;
    

    /**
    * ���췽��
    */
    public PCTD() {
        KeyGeneration(1024,64);
    }

    /**
    * ����ϵͳ��������(g,N)   �û���Կpk    
    */
    public static void KeyGeneration(int bitLength,int certainty) {
        
    	//p,qΪ������ɵ�����512bit�Ĵ�����
    	p = new BigInteger(bitLength / 2, certainty, new Random());     //���ɲ���p(512bit)
		q = new BigInteger(bitLength / 2, certainty, new Random());     //���ɲ���q(512bit)

        //lambda=lcm(p-1,q-1) ��С������
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                  .divide(p.subtract(BigInteger.ONE)
                           .gcd(q.subtract(BigInteger.ONE)));
        //n=p*q
        n = p.multiply(q); 
        //nsquare=n^2
        nsquare = n.multiply(n);
        System.out.println("nsquare:" + nsquare);
        
        //lambda����Ԫ
        lambda0=lambda.modInverse(nsquare);
        //�ֽ�lambda   lambda1=lambda0*lambda/2; lambda2=lambda-lambda1
        lambda1=lambda0.multiply(lambda).divide(new BigInteger("2"));      
		lambda2=lambda0.multiply(lambda).subtract(lambda1);               
        
        //aΪ�������ȡ��Z*_n^2
        //g=-a^2n mod n^2
        BigInteger a = new BigInteger("2"); 
        BigInteger two = new BigInteger("2");
        g = new BigInteger("0");
        g = (a.modPow(n.multiply(two), nsquare)).negate().mod(nsquare); 
        
    }
    
    /** 
   	 * @param sk �û�˽Կ
   	 * @return �����û���Կ
   	 * ��Կ����
   	 */    
    public static BigInteger  publicKeyGeneration(BigInteger sk)
    {
    	//���ع�Կ pk=(g^sk)mod n^2
    	return g.modPow(sk, nsquare); 
    }

    /** 
	 * @param m ����
	 * @return �������� 
	 * ����
	 */    
    public static Ciphertext Encryption(BigInteger m, BigInteger pk) {
    	
    	Ciphertext C0 = new Ciphertext();
    	
        //ѡȡ�����
        Random random = new Random();
        BigInteger r = new BigInteger(512, random);
        

        //�������ĵ�ֵ
        //C1=pk^r(1+mN)  C2=g^r mod n^2
        C0.C1 = (pk.modPow(r, nsquare)
                   .multiply(m.multiply(n).add(BigInteger.ONE).mod(nsquare)));
        C0.C2 = g.modPow(r, nsquare);

        return C0;
    }

    /** 
	 * @param x ������
	 * @return ���ش�����
	 * ����L(X)=(X-1)/n
	 */
    public static BigInteger functionL(BigInteger x) {
        return (x.subtract(BigInteger.ONE)).divide(n);
    }

    /** 
   	 * @param C  ����    
   	 * @param sk ˽Կ
   	 * @return ��������
   	 * �û�����
   	 */
    public static BigInteger weakDecryption(Ciphertext C, BigInteger sk) {
    	
    	
        BigInteger m = new BigInteger("0");

        //m=L(C1 / C2^sk mod nsquare)    	  
        m = functionL(C.C1.divide(C.C2.modPow(sk, nsquare)));
        System.out.println("����(�û�)m=" + m);

        return m;
    }

    /** 
   	 * @param C  ����    
   	 * @return ��������
   	 * ϵͳ����
   	 */
    public static BigInteger strongDecryption(Ciphertext C) {
    	
        BigInteger m = new BigInteger("0");
        
        //��lambda����Ԫ
        lambda0 = lambda.modInverse(n);

        // m = [ L(C1^lambda mod nsquare)*lambda0 ]mod n
        BigInteger X1 = C.C1.modPow(lambda, nsquare);
        m = functionL(X1.multiply(lambda0)).mod(n);
        System.out.println("���ܣ�ϵͳ��m=" + m);

        return m;
    }

    /** 
   	 * @param C1  ���� ���   
   	 * @return ��������
   	 * �ֲ����ܵ�һ��
   	 */
    public static BigInteger partialDecryptionOne(BigInteger C1) {
    	
      // �����һ�����ܵ��м����ģ�(C1^lambda1)mod n^2
        BigInteger C11 = C1.modPow(lambda1, nsquare);
        System.out.println("C11=" + C11);

        return C11;
    }

    /** 
   	 * @param C1  ���� ���   
   	 * @param C11  ��һ�����ܺ�Ĳ�������
   	 * @return ��������
   	 * �ֲ����ܵڶ���
   	 */
    public static BigInteger partialDecryptionTwo(BigInteger C11, BigInteger C1) {
    	
        //�ڶ�������   C12=(C1^lambda) mod n^2
        // m= functionL(C11 * C12 mod n^2) 
        BigInteger C12 = C1.modPow(lambda2, nsquare);
        BigInteger m = functionL((C11.multiply(C12)).mod(nsquare));
        System.out.println("�ֲ�����m=" + m);

        return m;
    }

    /** 
   	 * @param C ����
   	 * @return ����ˢ�º������
   	 * ����ˢ��
   	 */
    public static Ciphertext refreshCipher(Ciphertext C, BigInteger pk) {
    	
        Ciphertext NC = new Ciphertext();
        
        //���������r1
        Random random = new Random();
        BigInteger r1 = new BigInteger(512, random);
        // nc1=(pk.pow(r1.intValue())).multiply(C.C1);
        //nc2=(g.pow(r1.intValue())).multiply(C.C2);
        NC.C1 = (pk.modPow(r1, nsquare).multiply(C.C1)).mod(nsquare);
        NC.C2 = (g.modPow(r1, nsquare).multiply(C.C2)).mod(nsquare);
        System.out.println("new cipher:");
        NC.printCipher();
        System.out.println("m:" + strongDecryption(NC));
        
        return NC;
    }

    public static void main(String[] args) {
        // TODO Auto-generated method stub
    	
        PCTD pctd = new PCTD();
        
        //��������m=48(sk=9);
        BigInteger sk=new BigInteger("9");
        BigInteger pk=publicKeyGeneration(sk);
        Ciphertext C=PCTD.Encryption(new BigInteger("48"),pk);
        C.printCipher();
        
        //�û�����
        PCTD.weakDecryption(C, sk);
        
        //ϵͳ����
        PCTD.strongDecryption(C);
        
        //ϵͳ�ֲ�����
        //��һ��
        BigInteger C11=PCTD.partialDecryptionOne(C.C1);
        
        //�ڶ���
        BigInteger C12=PCTD.partialDecryptionTwo(C11, C.C1);
        
        //����ˢ��
        Ciphertext C_n=PCTD.refreshCipher(C, pk);
        //������֤
        PCTD.strongDecryption(C_n);
        
    }
}