package be.nitroxis.security;

/**
 * Lists the different supported encryption modes.
 *
 * @author Olivier Houyoux
 * @see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
 */
public enum Mode {

    CIPHER_BLOCK_CHAINING("CBC"),

    CIPHER_FEEDBACK("CFB"),

    OUTPUT_FEEDBACK("OFB"),

    ELECTRONIC_CODE_BOOK("ECB");

    private final String name;

    private Mode(final String name) {
        this.name = name;
    }

    /**
     * Returns the {@code Cipher} compatible name of this {@code Mode}.
     *
     * @return the {@code Cipher} compatible name
     */
    public String getName() {
        return name;
    }
}
