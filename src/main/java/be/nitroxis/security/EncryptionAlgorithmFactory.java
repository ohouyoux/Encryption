package be.nitroxis.security;

import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Helps to correctly instantiate new {@code SymmetricEncryptionAlgorithm} objects for a given encryption {@code Algorithm}.
 *
 * @author Olivier Houyoux
 */
@ThreadSafe
public class EncryptionAlgorithmFactory
        implements Factory<
            SymmetricEncryptionAlgorithm<byte[], byte[], GeneralSecurityException>,
            GeneralSecurityException> {

    private final Algorithm algorithm;

    private final Mode mode;

    private final Padding padding;

    /**
     * Instantiates a new {@code EncryptionAlgorithmFactory}.
     *
     * @param algorithm the concrete encryption {@code Algorithm} to be used
     */
    public EncryptionAlgorithmFactory(final Algorithm algorithm, final Mode mode, final Padding padding) {
        this.algorithm = checkNotNull(algorithm, "Encryption algorithm should not be null");
        this.mode = checkNotNull(mode, "Encryption mode should not be null");
        this.padding = checkNotNull(padding, "Encryption padding should not be null");
    }

    @Override
    public SymmetricEncryptionAlgorithm<byte[], byte[], GeneralSecurityException> newInstance()
            throws GeneralSecurityException {

        String name = algorithm.name();
        KeyGenerator generator = KeyGenerator.getInstance(name);
        SecretKey key = generator.generateKey();
        String transformation = new StringBuilder(name)
                .append('/')
                .append(mode.getName())
                .append('/')
                .append(padding.getName())
                .toString();
        Cipher cipher = Cipher.getInstance(transformation);

        DefaultEncrypter encrypter = new DefaultEncrypter(key, cipher);
        Decrypter<byte[], byte[], GeneralSecurityException> decrypter = new DefaultDecrypter(key, cipher);;

        return new SymmetricEncryptionAlgorithm<>(encrypter, decrypter);
    }
}
