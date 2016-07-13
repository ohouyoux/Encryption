package be.nitroxis.security;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Helps to build new {@code SecretKey} instances.
 *
 * @author Olivier Houyoux
 */
public class SecretKeyBuilder implements Builder<SecretKey, GeneralSecurityException> {

    private Algorithm algorithm;

    /**
     * Configures this {@code SecretKeyBuilder} with a given {@code Algorithm}.
     *
     * @param algorithm the {@code Algorithm}
     * @return this {@code SecretKeyBuilder} configured with the given {@code Algorithm}
     */
    public SecretKeyBuilder withAlgorithm(final Algorithm algorithm) {
        this.algorithm = checkNotNull(algorithm, "Algorithm should not be null");

        return this;
    }

    @Override
    public SecretKey build() throws GeneralSecurityException {
        String name = algorithm.name();
        KeyGenerator generator = KeyGenerator.getInstance(name);

        return generator.generateKey();
    }
}


