package be.nitroxis.security;

import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Helps to correctly instantiate new {@code EncryptionAlgorithm} objects for a given encryption
 * {@code Algorithm}.
 *
 * @author Olivier Houyoux
 */
@ThreadSafe
public class EncryptionAlgorithmFactory
        implements Factory<
        EncryptionAlgorithm<byte[], byte[], GeneralSecurityException>,
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
    public EncryptionAlgorithm<byte[], byte[], GeneralSecurityException> newInstance()
            throws GeneralSecurityException {

        SecretKey key = new SecretKeyBuilder().withAlgorithm(algorithm).build();
        Factory<AlgorithmParameterSpec, GeneralSecurityException> factory = new AlgorithmParameterSpecFactory(mode);
        AlgorithmParameterSpec specification = factory.newInstance();
        Encrypter<byte[], byte[], GeneralSecurityException> encrypter =
                new DefaultEncrypter(key, algorithm, mode, padding, specification);
        Decrypter<byte[], byte[], GeneralSecurityException> decrypter =
                new DefaultDecrypter(key, algorithm, mode, padding, specification);

        return new EncryptionAlgorithm<>(encrypter, decrypter);
    }
}
