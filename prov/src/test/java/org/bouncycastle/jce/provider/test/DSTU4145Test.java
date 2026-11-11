package org.bouncycastle.jce.provider.test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class DSTU4145Test
    extends SimpleTest
{

    public String getName()
    {
        return "DSTU4145";
    }

    public void performTest()
        throws Exception
    {
        implDSTU4145Test();
        generationTest();
        //parametersTest();
        generateFromCurveTest();
        unrecognisedKeyInitSignTest();
        signatureEncodingTest();
    }

    /**
     * A DSTU 4145 signature is an OCTET STRING holding s and r as two halves of equal length. An
     * odd number of octets is therefore not a signature, but used to be taken as one with the
     * octet left over ignored - the last, or for the little endian form the first - so an octet
     * of any value could be added to a signature without it ceasing to verify. Nor may anything
     * that is not an OCTET STRING at all leave verify() as an unchecked exception.
     */
    private void signatureEncodingTest()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2.0"));

        KeyPair pair = keyGen.generateKeyPair();

        signatureEncodingTest("DSTU4145", pair);
        signatureEncodingTest("GOST3411WITHDSTU4145LE", pair);
    }

    private void signatureEncodingTest(String algorithm, KeyPair pair)
        throws Exception
    {
        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        Signature sgr = Signature.getInstance(algorithm, "BC");

        sgr.initSign(pair.getPrivate());

        sgr.update(message);

        byte[] sigBytes = sgr.sign();
        byte[] octets = ASN1OctetString.getInstance(sigBytes).getOctets();

        isTrue(algorithm + " signature not two halves", (octets.length % 2) == 0);

        sgr.initVerify(pair.getPublic());

        // an octet too many, at either end and of any value
        checkNotASignature(algorithm + " signature with a zero octet appended", sgr, message,
            new DEROctetString(Arrays.append(octets, (byte)0)).getEncoded());
        checkNotASignature(algorithm + " signature with a non-zero octet appended", sgr, message,
            new DEROctetString(Arrays.append(octets, (byte)0x7f)).getEncoded());
        checkNotASignature(algorithm + " signature with a zero octet prepended", sgr, message,
            new DEROctetString(Arrays.prepend(octets, (byte)0)).getEncoded());
        checkNotASignature(algorithm + " signature with a non-zero octet prepended", sgr, message,
            new DEROctetString(Arrays.prepend(octets, (byte)0x7f)).getEncoded());

        // an octet too few, and none
        checkNotASignature(algorithm + " signature with its last octet removed", sgr, message,
            new DEROctetString(Arrays.copyOf(octets, octets.length - 1)).getEncoded());
        checkNotASignature(algorithm + " signature of no octets", sgr, message,
            new DEROctetString(new byte[0]).getEncoded());

        // damage to the encoding around the octets
        checkNotASignature(algorithm + " signature with data following it", sgr, message,
            Arrays.append(sigBytes, (byte)0));
        checkNotASignature(algorithm + " signature truncated", sgr, message,
            Arrays.copyOf(sigBytes, sigBytes.length - 1));

        // nothing, and things which are not an OCTET STRING
        checkNotASignature(algorithm + " signature of no length", sgr, message, new byte[0]);
        checkNotASignature(algorithm + " signature that is a NULL", sgr, message, DERNull.INSTANCE.getEncoded());
        checkNotASignature(algorithm + " signature that is a SEQUENCE", sgr, message, new DERSequence().getEncoded());

        // none of which may disturb the object: it has to be ready for the next message each time.
        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail(algorithm + " verification failed after malformed signatures");
        }
    }

    /**
     * Something that is not a signature at all is reported by verify() returning false or by a
     * SignatureException, the two answers the JCA has for it - never by returning true, and never
     * by an unchecked exception.
     */
    private void checkNotASignature(String label, Signature sgr, byte[] message, byte[] sigBytes)
        throws Exception
    {
        sgr.update(message);

        try
        {
            if (sgr.verify(sigBytes))
            {
                fail(label + " verified");
            }
        }
        catch (SignatureException e)
        {
            // also fine
        }
    }

    private void unrecognisedKeyInitSignTest()
        throws Exception
    {
        // a private key that is neither BCDSTU4145PrivateKey nor org.bouncycastle.jce.interfaces.ECKey
        KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA", "BC");
        rsaKeyGen.initialize(1024);
        KeyPair rsaPair = rsaKeyGen.generateKeyPair();

        Signature sgr = Signature.getInstance("DSTU4145", "BC");

        try
        {
            sgr.initSign(rsaPair.getPrivate());
            fail("no exception on initSign with non-EC private key");
        }
        catch (java.security.InvalidKeyException e)
        {
            // expected - mirrors engineInitVerify behaviour for a non-EC public key
        }
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());
        runTest(new DSTU4145Test());
    }
    
    static final BigInteger r = new BigInteger("00f2702989366e9569d5092b83ac17f918bf040c487a", 16);
    static final BigInteger s = new BigInteger("01dd460039db3be70392d7012f2a492d3e59091ab7a6", 16);
    
    private void generationTest() throws Exception
    {
        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16), null, null);

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
            new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));
        
        SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));
        SecureRandom keyRand = new TestRandomBigInteger(Hex.decode("0000955CD7E344303D1034E66933DC21C8044D42ADB8"));
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");
        keyGen.initialize(spec, keyRand);
        KeyPair pair = keyGen.generateKeyPair();
        
        Signature sgr = Signature.getInstance("DSTU4145", "BC");

        sgr.initSign(pair.getPrivate(), k);

        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(pair.getPublic());

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("DSTU4145 verification failed");
        }

        BigInteger[] sig = decode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
        }
    }

    private void generateFromCurveTest()
        throws Exception
    {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSTU4145", "BC");

        for (int i = 0; i != 10; i++)
        {
            keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + i));
        }

        try
        {
            keyGen.initialize(new ECGenParameterSpec("1.2.804.2.1.1.1.1.3.1.1.2." + 10));
            fail("no exception");
        }
        catch (InvalidAlgorithmParameterException e)
        {
            isTrue("unknown curve name: 1.2.804.2.1.1.1.1.3.1.1.2.10".equals(e.getMessage()));
        }
    }

    private void implDSTU4145Test()
        throws Exception
    {

        SecureRandom k = new TestRandomBigInteger(Hex.decode("00137449348C1249971759D99C252FFE1E14D8B31F00"));

        ECCurve.F2m curve = new ECCurve.F2m(173, 1, 2, 10, BigInteger.ZERO, new BigInteger("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", 16), null, null);

        ECParameterSpec spec = new ECParameterSpec(
            curve,
            curve.createPoint(new BigInteger("BE6628EC3E67A91A4E470894FBA72B52C515F8AEE9", 16), new BigInteger("D9DEEDF655CF5412313C11CA566CDC71F4DA57DB45C", 16)),
            new BigInteger("800000000000000000000189B4E67606E3825BB2831", 16));

        ECPrivateKeySpec priKey = new ECPrivateKeySpec(
            new BigInteger("955CD7E344303D1034E66933DC21C8044D42ADB8", 16), // d
            spec);

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
            curve.createPoint(new BigInteger("22de541d48a75c1c3b8c7c107b2551c5093c6c096e1", 16), new BigInteger("1e5b602efc0269d61e64d97c9193d2788fa05c4b7fd5", 16)),
            spec);

        Signature sgr = Signature.getInstance("DSTU4145", "BC");
        KeyFactory f = KeyFactory.getInstance("DSTU4145", "BC");
        PrivateKey sKey = f.generatePrivate(priKey);
        PublicKey vKey = f.generatePublic(pubKey);

        sgr.initSign(sKey, k);

        byte[] message = new byte[]{(byte)'a', (byte)'b', (byte)'c'};

        sgr.update(message);

        byte[] sigBytes = sgr.sign();

        sgr.initVerify(vKey);

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("DSTU4145 verification failed");
        }

        BigInteger[] sig = decode(sigBytes);

        if (!r.equals(sig[0]))
        {
            fail(
                ": r component wrong." + Strings.lineSeparator()
                    + " expecting: " + r + Strings.lineSeparator()
                    + " got      : " + sig[0].toString(16));
        }

        if (!s.equals(sig[1]))
        {
            fail(
                ": s component wrong." + Strings.lineSeparator()
                    + " expecting: " + s + Strings.lineSeparator()
                    + " got      : " + sig[1].toString(16));
        }
    }

    private BigInteger[] decode(
        byte[] encoding)
        throws IOException
    {
        ASN1OctetString octetString = (ASN1OctetString)ASN1OctetString.fromByteArray(encoding);
        encoding = octetString.getOctets();

        byte[] r = new byte[encoding.length / 2];
        byte[] s = new byte[encoding.length / 2];

        System.arraycopy(encoding, 0, s, 0, encoding.length / 2);

        System.arraycopy(encoding, encoding.length / 2, r, 0, encoding.length / 2);

        BigInteger[] sig = new BigInteger[2];

        sig[0] = new BigInteger(1, r);
        sig[1] = new BigInteger(1, s);

        return sig;
    }
}
