package be.nitroxis.security;

/**
 * Defines how to decrypt any message.
 *
 * @param <C> the type of encrypted message (cipher text)
 * @param <P> the type of decrypted message (plaintext)
 * @param <E> the type of {@code Exception} that may be thrown by the decryption algorithm
 * @author Olivier Houyoux
 */
public interface Decrypter<C, P, E extends Exception> {

    /**
     * Decrypts an encoded message.
     *
     * @param message the encoded message
     * @return the decrypted message
     * @throws E if the decryption of {@code message} fails
     */
    P decrypt(C message) throws E;
}
