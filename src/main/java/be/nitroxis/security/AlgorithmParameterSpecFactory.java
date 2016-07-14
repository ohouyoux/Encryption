package be.nitroxis.security;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A concrete {@code Factory} for {@code AlgorithmParameterSpec} based on the current {@code Mode} of operation.
 *
 * @author Olivier Houyoux
 */
public class AlgorithmParameterSpecFactory implements Factory<AlgorithmParameterSpec, GeneralSecurityException> {

    private final Mode mode;

    /**
     * Instantiates a new {@code AlgorithmParameterSpecFactory}.
     *
     * @param mode the {@code Mode} of operation for which a new {@code AlgorithmParameterSpec} must be created
     */
    public AlgorithmParameterSpecFactory(final Mode mode) {
        this.mode = checkNotNull(mode, "Mode should not be null");
    }

    @Override
    public AlgorithmParameterSpec newInstance() throws GeneralSecurityException {
        AlgorithmParameterSpec spec;

        // We need to ensure that the same PRNG is used no matter where the code is running, hence we specify the
        // algorithm (> SHA1PRNG on Windows, NativePRNG on Linux)
        // We must never call setSeed() on the SecureRandom to inadvertently provide a predictable seed
        // But it could be more secure to periodically call setSeed(random.generateSeed(int))
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv;

        switch(mode) {
            case GALOIS_COUNTER:
                iv = new byte[12];
                random.nextBytes(iv);
                spec = new GCMParameterSpec(16 * 8, iv);
                break;

            default:
                iv = new byte[16];
                random.nextBytes(iv);
                spec = new IvParameterSpec(iv);
        }

        return spec;
    }
}
