package be.nitroxis.security;

import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A {@code Decrypter} template.
 *
 * @author Olivier Houyoux
 */
@ThreadSafe
class DefaultDecrypter implements Decrypter<byte[], byte[], GeneralSecurityException> {

    private final SecretKey key;

    private final Cipher cipher;

    /**
     * Instantiates a new {@code DefaultDecrypter}.
     *
     * @param key the {@code SecretKey} used to encrypt the plaintext message
     * @param cipher the {@code Cipher} used to encrypt the plaintext message
     */
    DefaultDecrypter(final SecretKey key, final Cipher cipher) {
        this.key = checkNotNull(key, "Secret key should not be null");
        this.cipher = checkNotNull(cipher, "Cipher should not be null");
    }

    @Override
    public byte[] decrypt(final byte[] message) throws GeneralSecurityException {
        checkNotNull(message, "Plaintext message should not be null");
        byte[] iv = cipher.getIV();
        IvParameterSpec spec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(message);
    }
}
