package be.nitroxis.security;

/**
 * Defines how to create an {@code Object}.
 *
 * @param <R> the type of {@code Object} to instantiate
 * @param <E> the type of {@code Exception} that could be throw if the {@code Object} could not be created
 * @author Olivier Houyoux
 */
public interface Factory<R, E extends Exception> {

    /**
     * Instantiates a new {@code Object}.
     *
     * @return the new {@code Object}
     * @throws E if the {@code Object} could not be created
     */
    R newInstance() throws E;
}
