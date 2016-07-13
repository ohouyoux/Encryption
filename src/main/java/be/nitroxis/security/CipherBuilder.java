package be.nitroxis.security;

import javax.crypto.Cipher;

import java.security.GeneralSecurityException;

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
    @Override
    public Cipher build() throws GeneralSecurityException {
        String transformation = new StringBuilder(algorithm.name())
                .append('/')
                .append(mode.getName())
                .append('/')
                .append(padding.getName())
                .toString();

        return Cipher.getInstance(transformation);
    }
}
