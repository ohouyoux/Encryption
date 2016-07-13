package be.nitroxis.security;

import javax.crypto.spec.IvParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A concrete {@code Factory} for {@code AlgorithmParameterSpec} based on the current {@code Mode} of operation.
 *
 * @author Olivier Houyoux
 */
public class AlgorithmParameterSpecFactory implements Factory<AlgorithmParameterSpec, RuntimeException> {

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
    public AlgorithmParameterSpec newInstance() {
        AlgorithmParameterSpec spec;

        switch(mode) {
            case GALOIS_COUNTER:
                throw new UnsupportedOperationException();
                //break;

            default:
                // TODO implement the default behavior the right way
                byte[] iv = null;
                spec = new IvParameterSpec(iv);
        }

        return spec;
    }
}
