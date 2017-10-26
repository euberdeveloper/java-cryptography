package cryptography;

import java.util.Random;

/**
 * The class to encrypt/decrypt with the Vigenere Cipher Algorithm, extended to
 * all Unicode characters.
 * @author Eugenio Vinicio Berretta, Valdagno 23/10/2017
 */
public final class UnicodeVigenereCipher implements Cipher {
    
    //FIELDS
    
    /**
     * The key of the cipher. It can be any String, with any length and 
     * Unicode character.
     */
    private String key;
    
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
     * and lastDecryptedText become empty strings.
     */
    public UnicodeVigenereCipher() {
        this.key = this.generateRandomKey();
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted or decrypted, depending on the given boolean. The result is 
     * saved in this.lastEncryptedText or this.lastDecryptedText.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted text will be empty
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     */
    public UnicodeVigenereCipher(String text, boolean encryption) {
        this.key = this.generateRandomKey();
        if(encryption) {
            this.encryptText(text);
            this.lastDecryptedText = "";
        }
        else {
            this.decryptText(text);
            this.lastEncryptedText = "";
        }
    }
    
    /**
     * Constructor of the class. The key is randomly chosen. lastEncryptedText
     * and lastDecryptedText become empty strings.
     * @param length int: The length of the key. It must be positive
     */
    public UnicodeVigenereCipher(int length) {
        this.key = this.generateRandomKey(length);
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted. The result is saved in this.lastEncryptedText.
     * @param length int: The length of the key, it must be positive
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     */
    public UnicodeVigenereCipher(int length, String text) {
        this.key = this.generateRandomKey(length);
        this.encryptText(text);
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class.
     * @param key String: The key of the cipher. lastEncryptedText and 
     * lastDecryptedText become empty strings.
     * @throws IllegalCipherKeyException If the key is null
     */
    public UnicodeVigenereCipher(String key) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
        this.key = key;
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText.
     * @param key String: The key to encrypt/decrypt the text.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted/decrypted text will be empty
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     * @throws IllegalCipherKeyException If the key is null
     */
    public UnicodeVigenereCipher(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
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
     * @return String: the class field key
     */
    public String getKey() {
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
     * @param key String: The new value of the key class field.
     * @throws IllegalCipherKeyException If the key is null
     */
    public void setKey(String key) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
        this.key = key;
    }
    
    /**
     * Setter method of the field key. It does also an encryption/decryption.
     * @param key String: The new value of the key class field.
     * @param text String: The text to encrypt/decrypt
     * @param encryption boolean: True if you want to encrypt, false if you 
     * want to decrypt
     * @throws IllegalCipherKeyException If the key is null
     */
    public void setKey(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
        this.key = key;
        if(encryption) {
            this.encryptText(text);
        }
        else {
            this.decryptText(text);
        }
    }
    
    //PRIVATE METHODS
    
    /**
     * This method generate a random key.
     * @return String: The generated random key
     */
    private String generateRandomKey() {
        StringBuilder key = new StringBuilder();
        int length = new Random().nextInt(100);
        for(int i = 0; i < length; i++) 
        {
            key.append((char) new Random().nextInt());
        }
        return key.toString();
    }
    
    /**
     * This method generate a random key.
     * @param length int: The length of the key
     * @return String: The generated random key
     */
    private String generateRandomKey(int length) {
        if(length < 1) {
            throw new IllegalArgumentException("The length must be positive");
        }
        StringBuilder key = new StringBuilder();
        for(int i = 0; i < length; i++) 
        {
            key.append((char) new Random().nextInt());
        }
        return key.toString();
    }
    
    //PUBLIC METHODS
    
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
        int keyLength = this.key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + this.key.charAt(j)));
            j = (j == keyLength - 1) ? 0 : j + 1;
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
        int keyLength = this.key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - this.key.charAt(j)));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //PRIVATE STATIC METHODS
    
    /**
     * This method checks if the given key is valid.
     * @param key String: The key that you want to check
     * @throws IllegalCipherKeyException If the key is not valid (null).
     */
    private static void checkKey(String key) throws IllegalCipherKeyException {
        if(key == null) {
            throw new IllegalCipherKeyException();
        }
    }
    
    //PUBLIC STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key. All characters
     * are encrypted.
     * @param key String: It can be any Unicode String value
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     * @return String: The encrypted text, an empty String in case text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is null
     */
    public static String encryptText(String key, String text) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        int keyLength = key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + key.charAt(j) - 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. All characters
     * are decrypted.
     * @param key String: It can be any Unicode String value
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is null
     */
    public static String decryptText(String key, String text) throws IllegalCipherKeyException {
        UnicodeVigenereCipher.checkKey(key);
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int keyLength = key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - key.charAt(j) + 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        return decryptedText.toString();
    }
    
}
