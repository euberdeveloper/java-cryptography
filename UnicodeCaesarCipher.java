package cryptography;

import java.util.Random;

/**
 * The class to encrypt/decrypt with the Caesar Cipher Algorithm, extended to
 * all Unicode characters.
 * @author Eugenio Vinicio Berretta, Valdagno 22/10/2017
 */
public final class UnicodeCaesarCipher implements Cipher {
    
    //FIELDS
    
    /**
     * The key of the cipher. It can be any short, either negative or positive. If
     * it is zero then the text does not change after encryption.
     */
    private short key;
    
    /**
     * The last encrypted text. It is empty if the cipher has been never used
     * to encrypt a text.
     */
    private String lastEncryptedText;
    
    /**
     * The last decrypted text. It is empty if the cipher has been never used
     * to decrypt a text.
     */
    private String lastDecryptedText;
    
    //CONSTRUCTORS
    
    /**
     * Constructor of the class. The key is randomly chosen. lastEncryptedText
     * and lastDecryptedText become empty strings. The key will not be zero.
     */
    public UnicodeCaesarCipher() {
        this.key = (short) (new Random().nextInt() + 1);
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted and the result is saved in this.lastEncryptedText. The key will
     * not be zero.
     * @param text String: The text that you want to encrypt. If it is 
     * null or empty then the encrypted text will be empty
     */
    public UnicodeCaesarCipher(String text) {
        this.key = (short) (new Random().nextInt() + 1);
        this.encryptText(text);
        this.lastDecryptedText = "";    
    }
    
    /**
     * Constructor of the class. lastEncryptedText and lastDecryptedText become 
     * empty strings.
     * @param key short: The key of the cipher, any short is accepted. If it is zero
     * then the encrypted/decrypted text is equal to the text
     */
    public UnicodeCaesarCipher(short key) {
        this.key = key;
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText.
     * @param key short: The key to encrypt/decrypt the text, any short is accepted.
     * If it is zero then the encrypted/decrypted text is equal to the text.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted/decrypted text will be empty
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     */
    public UnicodeCaesarCipher(short key, String text, boolean encryption) {
        this.key = key;
        if(encryption) {
            this.encryptText(text);
            this.lastDecryptedText = "";
        }
        else {
            this.decryptText(text);
            this.lastEncryptedText = "";
        }
    }
    
    //GETTERS
    
    /**
     * Getter method of the field key.
     * @return short: the class field key
     */
    public short getKey() {
        return this.key;
    }
    
    /**
     * Getter method of the field lastEncryptedText. It is empty if the cipher 
     * has been never used to encrypt a text.
     * @return String: the class field lastEncryptedText
     */
    public String getLastEncryptedText() {
        return this.lastEncryptedText;
    }
    
    /**
     * Getter method of the field lastDecryptedText. It is empty if the cipher 
     * has been never used to decrypt a text.
     * @return String: the class field lastDecryptedText
     */
    public String getLastDecryptedText() {
        return this.lastDecryptedText;
    }
    
    //SETTERS
    
    /**
     * Setter method of the field key.
     * @param key short: The new value of the key class field. Any short 
     * accepted. If it is zero then the encrypted/decrypted text is equal to the text.
     */
    public void setKey(short key) {
        this.key = key;
    }
    
    /**
     * Setter method of the field key. It does also an encryption/decryption.
     * @param key short: The new value of the key class field. Any short 
     * accepted. If it is zero then the encrypted/decrypted text is equal to the
     * text.
     * @param text String: The text to encrypt/decrypt. If it is null or empty 
     * then the encrypted/decrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you 
     * want to decrypt
     */
    public void setKey(short key, String text, boolean encryption) {
        this.key = key;
        if(encryption) {
            this.encryptText(text);
        }
        else {
            this.decryptText(text);
        }
    }
    
    //METHODS
    
    /**
     * It returns the given text encrypted with this.key key. All characters
     * are encrypted. The result is also assigned to this.lastEncryptedText.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     * @return String: The encrypted text, an empty String if the text equals
     * null or is an empty String
     */
    @Override
    public String encryptText(String text) {
        if(text == null || text.isEmpty()) {
            this.lastEncryptedText = "";
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + this.key));
        }
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with the this.key key. All characters
     * are decrypted. The result is also assigned to this.lastDecryptedText.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     */
    @Override
    public String decryptText(String text) {
        if(text == null || text.isEmpty()) {
            this.lastDecryptedText = "";
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - this.key));
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key. All characters
     * are encrypted.
     * @param key short: It can be any short value, either positive or negative,
     * if it is zero then the text does not change.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     * @return String: The encrypted text, an empty String in case text equals
     * null or is an empty String
     */
    public static String encryptText(short key, String text) {
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + key));
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. All characters
     * are decrypted.
     * @param key short: It can be any short value, either positive or negative,
     * if it is zero then the text does not change
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     */
    public static String decryptText(short key, String text) {
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - key));
        }
        return decryptedText.toString();
    }
    
}
