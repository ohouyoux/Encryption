package be.nitroxis.security;

import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * An {@code Encrypter} template.
 *
 * @author Olivier Houyoux
 */
@ThreadSafe
public class DefaultEncrypter implements Encrypter<byte[], byte[], GeneralSecurityException> {

    private final Cipher cipher;

    /**
     * Instantiates a new {@code DefaultEncrypter}.
     *
     * @param key the {@code SecretKey} used to encrypt the plaintext message
     * @param algorithm the {@code Algorithm} used for encrypting the plaintext
     * @param mode the {@code Mode} used for encrypting the plaintext
     * @param padding the {@code Padding} used for encrypting the plaintext
     * @param specification the encryption algorithm specification
     * @throws GeneralSecurityException if the encryption {@code Cipher} could not be created
     */
    public DefaultEncrypter(
            final SecretKey key,
            final Algorithm algorithm,
            final Mode mode,
            final Padding padding,
            final AlgorithmParameterSpec specification) throws GeneralSecurityException {

        checkNotNull(key, "Secret key should not be null");
        checkNotNull(algorithm, "Algorithm should not be null");
        checkNotNull(mode, "Mode should not be null");
        checkNotNull(padding, "Padding should not be null");
        checkNotNull(specification, "Algorithm specification must not be null");
        this.cipher = new CipherBuilder()
                .withAlgorithm(algorithm)
                .withMode(mode)
                .withPadding(padding)
                .withKey(key)
                .withSpecification(specification)
                .withOperationMode(Cipher.ENCRYPT_MODE)
                .build();
    }

    @Override
    public byte[] encrypt(final byte[] message) throws GeneralSecurityException {
        checkNotNull(message, "Plaintext message should not be null");

        return cipher.doFinal(message);
    }
}
