package cryptography;

/**
 * The interface root of all the ciphers classes.
 * @author Eugenio Vinicio Berretta, Valdagno 22/10/2017
 */
public interface Cipher {
    
    /**
     * It encrypt the given text and returns it. The property 
     * this.lastEncryptedText should get the result of the function as new 
     * value.
     * @param text String: The text that you want to encrypt.
     * @return String: The encrypted text.
     */
    public String encryptText(String text);
    
    /**
     * It decrypt the given text and returns it. The property 
     * this.lastDecryptedText should get the result of the function as new 
     * value.
     * @param text String: The text that you want to decrypt.
     * @return String: The decrypted text.
     */
    public String decryptText(String text);
    
}
