import java.math.BigInteger;

import java.util.Random;

/**
* 密文类，用来表示密文二元组
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
 * 双陷门同态加解密算法（Paillier cryptosystem with threshold decryption)
 * 
 * 密钥生成：
 * 1、选择两个大质数p和q
 * 2、计算 n = pq和 lambda= lcm (p - 1,q-1)
 * 3、选择随机整数a属于Z*_n^2,求生成元g=-a^2n mod n^2
 * 4、系统公开参数为（N，g）
 * 5、系统私钥为lambda，系统部分私钥为lambda1,lambda2
 * 6、用户私钥为sk
 * 7、用户公钥为pk=g^sk mod n^2
 * 
 * 加密:
 * 选择随机数r
 * 计算密文C=(C1,C2)  C1=pk^r(1+mN)  C2=g^r mod n^2
 * 其中m为明文
 * 
 * 用户解密：
 * m=L(C1/C2^sk mod n^2)
 * 
 * 系统解密：
 * m = L(C1^lambda mod n^2)* lambda.modInverse(n) mod n
 * 
 * 系统分步解密：
 * step1:C11=C1^lambda1 mod n^2
 * step2:C12=C11^lambda2 mod n^2
 *       m=L(C11,C12)
 * 
 * 其中L(u) = (u-1)/n;
 */

public class PCTD{
	
	//p,q是两个随机的质数 ;lambda = lcm(p-1, q-1)
    private static BigInteger p,q,lambda;
    
    //lambda0=modInverse(lambda);lambda1,lambda2为分解后的部分私钥
    private static BigInteger lambda0,lambda1,lambda2;
    
    //n=p*q
    public static BigInteger n;
    
    //nsquare=n*n
    public static BigInteger nsquare;
    
    //g为生成元
    public static BigInteger g;
    
    //用户私钥
    private  BigInteger sk;
    
    //用户公钥
    public BigInteger pk;
    

    /**
    * 构造方法
    */
    public PCTD() {
        KeyGeneration(1024,64);
    }

    /**
    * 生成系统公开参数(g,N)   用户公钥pk    
    */
    public static void KeyGeneration(int bitLength,int certainty) {
        
    	//p,q为随机生成的两个512bit的大素数
    	p = new BigInteger(bitLength / 2, certainty, new Random());     //生成参数p(512bit)
		q = new BigInteger(bitLength / 2, certainty, new Random());     //生成参数q(512bit)

        //lambda=lcm(p-1,q-1) 最小公倍数
        lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))
                  .divide(p.subtract(BigInteger.ONE)
                           .gcd(q.subtract(BigInteger.ONE)));
        //n=p*q
        n = p.multiply(q); 
        //nsquare=n^2
        nsquare = n.multiply(n);
        System.out.println("nsquare:" + nsquare);
        
        //lambda的逆元
        lambda0=lambda.modInverse(nsquare);
        //分解lambda   lambda1=lambda0*lambda/2; lambda2=lambda-lambda1
        lambda1=lambda0.multiply(lambda).divide(new BigInteger("2"));      
		lambda2=lambda0.multiply(lambda).subtract(lambda1);               
        
        //a为随机数，取自Z*_n^2
        //g=-a^2n mod n^2
        BigInteger a = new BigInteger("2"); 
        BigInteger two = new BigInteger("2");
        g = new BigInteger("0");
        g = (a.modPow(n.multiply(two), nsquare)).negate().mod(nsquare); 
        
    }
    
    /** 
   	 * @param sk 用户私钥
   	 * @return 返回用户公钥
   	 * 公钥生成
   	 */    
    public static BigInteger  publicKeyGeneration(BigInteger sk)
    {
    	//返回公钥 pk=(g^sk)mod n^2
    	return g.modPow(sk, nsquare); 
    }

    /** 
	 * @param m 明文
	 * @return 返回密文 
	 * 加密
	 */    
    public static Ciphertext Encryption(BigInteger m, BigInteger pk) {
    	
    	Ciphertext C0 = new Ciphertext();
    	
        //选取随机数
        Random random = new Random();
        BigInteger r = new BigInteger(512, random);
        

        //计算密文的值
        //C1=pk^r(1+mN)  C2=g^r mod n^2
        C0.C1 = (pk.modPow(r, nsquare)
                   .multiply(m.multiply(n).add(BigInteger.ONE).mod(nsquare)));
        C0.C2 = g.modPow(r, nsquare);

        return C0;
    }

    /** 
	 * @param x 大整数
	 * @return 返回大整数
	 * 函数L(X)=(X-1)/n
	 */
    public static BigInteger functionL(BigInteger x) {
        return (x.subtract(BigInteger.ONE)).divide(n);
    }

    /** 
   	 * @param C  密文    
   	 * @param sk 私钥
   	 * @return 返回明文
   	 * 用户解密
   	 */
    public static BigInteger weakDecryption(Ciphertext C, BigInteger sk) {
    	
    	
        BigInteger m = new BigInteger("0");

        //m=L(C1 / C2^sk mod nsquare)    	  
        m = functionL(C.C1.divide(C.C2.modPow(sk, nsquare)));
        System.out.println("解密(用户)m=" + m);

        return m;
    }

    /** 
   	 * @param C  密文    
   	 * @return 返回明文
   	 * 系统解密
   	 */
    public static BigInteger strongDecryption(Ciphertext C) {
    	
        BigInteger m = new BigInteger("0");
        
        //求lambda的逆元
        lambda0 = lambda.modInverse(n);

        // m = [ L(C1^lambda mod nsquare)*lambda0 ]mod n
        BigInteger X1 = C.C1.modPow(lambda, nsquare);
        m = functionL(X1.multiply(lambda0)).mod(n);
        System.out.println("解密（系统）m=" + m);

        return m;
    }

    /** 
   	 * @param C1  密文 组件   
   	 * @return 返回明文
   	 * 分步解密第一步
   	 */
    public static BigInteger partialDecryptionOne(BigInteger C1) {
    	
      // 计算第一步解密的中间密文：(C1^lambda1)mod n^2
        BigInteger C11 = C1.modPow(lambda1, nsquare);
        System.out.println("C11=" + C11);

        return C11;
    }

    /** 
   	 * @param C1  密文 组件   
   	 * @param C11  第一步解密后的部分密文
   	 * @return 返回明文
   	 * 分步解密第二步
   	 */
    public static BigInteger partialDecryptionTwo(BigInteger C11, BigInteger C1) {
    	
        //第二步解密   C12=(C1^lambda) mod n^2
        // m= functionL(C11 * C12 mod n^2) 
        BigInteger C12 = C1.modPow(lambda2, nsquare);
        BigInteger m = functionL((C11.multiply(C12)).mod(nsquare));
        System.out.println("分步解密m=" + m);

        return m;
    }

    /** 
   	 * @param C 密文
   	 * @return 返回刷新后的密文
   	 * 密文刷新
   	 */
    public static Ciphertext refreshCipher(Ciphertext C, BigInteger pk) {
    	
        Ciphertext NC = new Ciphertext();
        
        //生成随机数r1
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
        
        //加密明文m=48(sk=9);
        BigInteger sk=new BigInteger("9");
        BigInteger pk=publicKeyGeneration(sk);
        Ciphertext C=PCTD.Encryption(new BigInteger("48"),pk);
        C.printCipher();
        
        //用户解密
        PCTD.weakDecryption(C, sk);
        
        //系统解密
        PCTD.strongDecryption(C);
        
        //系统分步解密
        //第一步
        BigInteger C11=PCTD.partialDecryptionOne(C.C1);
        
        //第二步
        BigInteger C12=PCTD.partialDecryptionTwo(C11, C.C1);
        
        //密文刷新
        Ciphertext C_n=PCTD.refreshCipher(C, pk);
        //解密验证
        PCTD.strongDecryption(C_n);
        
    }
}