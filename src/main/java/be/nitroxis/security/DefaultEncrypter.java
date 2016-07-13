package be.nitroxis.security;

import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * An {@code Encrypter} template.
 *
 * @author Olivier Houyoux
 */
@ThreadSafe
class DefaultEncrypter implements Encrypter<byte[], byte[], GeneralSecurityException> {

    private final SecretKey key;

    private final Cipher cipher;

    /**
     * Instantiates a new {@code DefaultEncrypter}.
     *
     * @param key the {@code SecretKey} used to encrypt the plaintext message
     * @param cipher the {@code Cipher} used to encrypt the plaintext message
     */
    DefaultEncrypter(final SecretKey key, final Cipher cipher) {
        this.key = checkNotNull(key, "Secret key should not be null");
        this.cipher = checkNotNull(cipher, "Cipher should not be null");
    }

    @Override
    public byte[] encrypt(final byte[] message) throws GeneralSecurityException {
        checkNotNull(message, "Plaintext message should not be null");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(message);
    }
}
