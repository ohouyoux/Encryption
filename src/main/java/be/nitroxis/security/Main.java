package be.nitroxis.security;

import com.google.common.base.Charsets;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;

/**
 * Tests the encryption / decryption algorithms.
 *
 * @author Olivier Houyoux
 */
public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(final String[] args) throws Exception {
        Factory<SymmetricEncryptionAlgorithm<byte[], byte[], GeneralSecurityException>,
                GeneralSecurityException> factory =
                new EncryptionAlgorithmFactory(Algorithm.AES, Mode.CIPHER_BLOCK_CHAINING, Padding.PKCS7);
        SymmetricEncryptionAlgorithm<byte[], byte[], GeneralSecurityException> algorithm = factory.newInstance();

        String message = "This is a test";
System.out.println("Plaintext: " + message);
        byte[] plaintext = message.getBytes(Charsets.UTF_8);
        byte[] ciphertext = algorithm.encrypt(plaintext);
System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
        plaintext = algorithm.decrypt(ciphertext);
System.out.println("Decoded: " + new String(plaintext));
    }
}
