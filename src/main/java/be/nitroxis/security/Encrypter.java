package be.nitroxis.security;

/**
 * Defines how to encrypt any message.
 *
 * @param <P> the type of message to encrypt (plaintext)
 * @param <C> the type of encrypted message (cipher text)
 * @param <E> the type of {@code Exception} that may be thrown by the encryption algorithm
 * @author Olivier Houyoux
 */
public interface Encrypter<P, C, E extends Exception> {

    /**
     * Encrypts a message.
     *
     * @param message the message to encode
     * @return the encoded message
     * @throws E if the encryption of {@code message} fails
     */
    C encrypt(P message) throws E;
}
