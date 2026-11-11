package org.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.security.SignatureException;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;

public class SignatureSpiLe
    extends SignatureSpi
{
    void reverseBytes(byte[] bytes)
    {
        byte tmp;

        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] signature = ASN1OctetString.getInstance(super.engineSign()).getOctets();
        reverseBytes(signature);
        try
        {
            return (new DEROctetString(signature)).getEncoded();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[] sigBytes)
        throws SignatureException
    {
        byte[] bytes = null;

        try
        {
            bytes = ((ASN1OctetString)ASN1OctetString.fromByteArray(sigBytes)).getOctets();
        }
        catch (Exception e)
        {
            // no encoding at all, or one of something other than an OCTET STRING, as well as one
            // that cannot be read. The parent class refuses each of these in the same way, and
            // leaving it to do so means the message is consumed whichever way this method is left.
            return super.engineVerify(sigBytes);
        }

        reverseBytes(bytes);

        try
        {
            return super.engineVerify((new DEROctetString(bytes)).getEncoded());
        }
        catch (SignatureException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }
}
