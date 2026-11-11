package org.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.interfaces.ECKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SignatureSpi
    extends java.security.SignatureSpi
    implements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest                  digest;
    private DSAExt                  signer;

    public SignatureSpi()
    {
        this(new GOST3411Digest());
    }

    protected SignatureSpi(Digest digest)
    {
        this.digest = digest;
        this.signer = new ECGOST3410Signer();
    }

    protected void engineInitVerify(
        PublicKey   publicKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        // an elliptic curve key and nothing else: a GOST R 34.10-94 key belongs with the GOST3410
        // signature, and like any other key the signer cannot use ends at the InvalidKeyException below.
        if (publicKey instanceof ECPublicKey)
        {
            param = generatePublicKeyParameter(publicKey);
        }
        else
        {
            try
            {
                byte[]  bytes = publicKey.getEncoded();

                publicKey = BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(bytes));

                param = ECUtil.generatePublicKeyParameter(publicKey);
            }
            catch (Exception e)
            {
                throw new InvalidKeyException("can't recognise key type in DSA based signer");
            }
        }

        digest.reset();
        signer.init(false, param);
    }

    protected void engineInitSign(
        PrivateKey  privateKey)
        throws InvalidKeyException
    {
        CipherParameters    param;

        if (privateKey instanceof ECKey)
        {
            param = ECUtil.generatePrivateKeyParameter(privateKey);
        }
        else
        {
            // as for verification an elliptic curve key and nothing else.
            throw new InvalidKeyException("can't recognise key type in ECGOST3410 signer");
        }

        digest.reset();

        if (appRandom != null)
        {
            signer.init(true, new ParametersWithRandom(param, appRandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineUpdate(
        byte    b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[]  b,
        int     off,
        int     len) 
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            byte[]          sigBytes = new byte[64];
            BigInteger[]    sig = signer.generateSignature(hash);
            byte[]          r = sig[0].toByteArray();
            byte[]          s = sig[1].toByteArray();

            if (s[0] != 0)
            {
                System.arraycopy(s, 0, sigBytes, 32 - s.length, s.length);
            }
            else
            {
                System.arraycopy(s, 1, sigBytes, 32 - (s.length - 1), s.length - 1);
            }
            
            if (r[0] != 0)
            {
                System.arraycopy(r, 0, sigBytes, 64 - r.length, r.length);
            }
            else
            {
                System.arraycopy(r, 1, sigBytes, 64 - (r.length - 1), r.length - 1);
            }

            return sigBytes;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }
    
    protected boolean engineVerify(
        byte[]  sigBytes) 
        throws SignatureException
    {
        byte[]  hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        // s followed by r, 32 bytes each, is the whole of a signature: one that is any longer is
        // no more a signature than one that is too short, and reading only the first 64 bytes of
        // it would let anything at all be appended to a valid signature without it ceasing to verify.
        if (sigBytes.length != 64)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        BigInteger[]    sig;

        try
        {
            byte[] r = new byte[32]; 
            byte[] s = new byte[32];

            System.arraycopy(sigBytes, 0, s, 0, 32);

            System.arraycopy(sigBytes, 32, r, 0, 32);
            
            sig = new BigInteger[2];
            sig[0] = new BigInteger(1, r);
            sig[1] = new BigInteger(1, s);
        }
        catch (Exception e)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        return signer.verifySignature(hash, sig[0], sig[1]);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(
        String  param,
        Object  value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String      param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    static AsymmetricKeyParameter generatePublicKeyParameter(
            PublicKey key)
    throws InvalidKeyException
    {
        return (key instanceof BCECGOST3410PublicKey) ? ((BCECGOST3410PublicKey)key).engineGetKeyParameters() : ECUtil.generatePublicKeyParameter(key);
    }

    static public class noneEcGost3410
        extends SignatureSpi
    {
        public noneEcGost3410()
        {
            super(new NullDigest());
        }
    }
}
