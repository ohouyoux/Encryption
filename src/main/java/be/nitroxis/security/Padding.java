package be.nitroxis.security;

/**
 * Lists the different supported padding modes.
 *
 * @author Olivier Houyoux
 * @see https://en.wikipedia.org/wiki/Padding_(cryptography)
 */
public enum Padding {

    PKCS5("PKCS5Padding"),

    PKCS7("PKCS7Padding"),

    NO_PADDING("NoPadding");

    private final String name;

    private Padding(final String name) {
        this.name = name;
    }

    /**
     * Returns the {@code Cipher} compatible name of this {@code Padding}.
     *
     * @return the {@code Cipher} compatible name
     */
    public String getName() {
        return name;
    }
}
