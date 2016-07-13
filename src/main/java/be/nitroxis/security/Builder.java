package be.nitroxis.security;

/**
 * Defines how to build new {@code Object}s.
 *
 * @author Olivier Houyoux
 * @param <O> the type of {@code Object} to build
 * @param <E> the type of {@code Exception} that may be throw when the {@code Object} is being built
 */
public interface Builder<O, E extends Exception> {

    /**
     * Builds a new {@code Object}.
     *
     * @return the new {@code Object}
     * @throws E if the {@code Object} could not be built
     */
    O build() throws E;
}
