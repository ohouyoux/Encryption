package be.nitroxis.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Helps to build new {@code Cipher} instances.
 *
 * @author Olivier Houyoux
 */
public class CipherBuilder implements Builder<Cipher, GeneralSecurityException> {

    private Algorithm algorithm;

    private Mode mode;

    private Padding padding;

    private SecretKey key;

    private int opmode;

    private AlgorithmParameterSpec specification;

    /**
     * Configures this {@code CipherBuilder} with a given {@code Algorithm}.
     *
     * @param algorithm the {@code Algorithm}
     * @return this {@code CipherBuilder} configured with the given {@code Algorithm}
     */
    public CipherBuilder withAlgorithm(final Algorithm algorithm) {
        this.algorithm = checkNotNull(algorithm, "Algorithm should not be null");

        return this;
    }

    /**
     * Configures this {@code CipherBuilder} with a given {@code Mode}.
     *
     * @param mode the {@code Mode}
     * @return this {@code CipherBuilder} configured with the given {@code Mode}
     */
    public CipherBuilder withMode(final Mode mode) {
        this.mode = checkNotNull(mode, "Mode should not be null");

        return this;
    }

    /**
     * Configures this {@code CipherBuilder} with a given {@code Padding}.
     *
     * @param padding the {@code Padding}
     * @return this {@code CipherBuilder} configured with the given {@code Padding}
     */
    public CipherBuilder withPadding(final Padding padding) {
        this.padding = checkNotNull(padding, "Padding should not be null");

        return this;
    }

    /**
     * Configures this {@code CipherBuilder} with a given operation mode.
     *
     * @param opmode the new operation mode
     * @return the {@code CipherBuilder} configured with the given {@code opmode}
     */
    public CipherBuilder withOperationMode(final int opmode) {
        this.opmode = opmode;

        return this;
    }

    /**
     * Configures this {@code CipherBuilder} with a given {@code SecretKey}.
     *
     * @param key the {@code SecretKey}
     * @return this {@code CipherBuilder} configured with the given {@code SecretKey}
     */
    public CipherBuilder withKey(final SecretKey key) {
        this.key = checkNotNull(key, "Secret key should not be null");

        return this;
    }

    /**
     * Configures this {@code CipherBuilder} with a given {@code AlgorithmParameterSpec}.
     *
     * @param specification the {@code AlgorithmParameterSpec}
     * @return this {@code CipherBuilder} configured with the given {@code AlgorithmParameterSpec}
     */
    public CipherBuilder withSpecification(final AlgorithmParameterSpec specification) {
        this.specification = checkNotNull(specification, "Algorithm specification should not be null");

        return this;
    }

    @Override
    public Cipher build() throws GeneralSecurityException {
        String transformation = new StringBuilder(algorithm.name())
                .append('/')
                .append(mode.getName())
                .append('/')
                .append(padding.getName())
                .toString();
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(opmode, key, specification);

        return cipher;
    }
}
