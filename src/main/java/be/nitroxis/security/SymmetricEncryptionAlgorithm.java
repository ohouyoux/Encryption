package be.nitroxis.security;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * Defines how to symmetrically encode and decode messages.
 *
 * @param <P> the type of message to encrypt (plaintext)
 * @param <C> the type of encrypted message (cipher text)
 * @param <E> the type of {@code Exception} that may be thrown by the encryption algorithm
 * @author Olivier Houyoux
 */
public class SymmetricEncryptionAlgorithm<P, C, E extends Exception> implements Encrypter<P, C, E>, Decrypter<C, P, E> {

    private final Encrypter<P, C, E> encrypter;

    private final Decrypter<C, P, E> decrypter;

    /**
     * Instantiates a new {@code SymmetricEncryptionAlgorithm}.
     *
     * @param encrypter the {@code Encrypter} used to encrypt plaintext messages
     * @param decrypter the {@code Decrypter} used to decrypt cipher text messages
     */
    public SymmetricEncryptionAlgorithm(final Encrypter<P, C, E> encrypter, final Decrypter<C, P, E> decrypter) {
        this.encrypter = checkNotNull(encrypter, "Encrypter should not be null");
        this.decrypter = checkNotNull(decrypter, "Decrypter should not be null");
    }

    @Override
    public C encrypt(final P message) throws E {
        checkNotNull(message, "Plaintext message should not be null");

        return encrypter.encrypt(message);
    }

    @Override
    public P decrypt(final C message) throws E {
        checkNotNull(message, "Cipher text message should not be null");

        return decrypter.decrypt(message);
    }
}
