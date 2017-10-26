package cryptography;

import java.util.ArrayList;
import java.util.Random;

/**
 * The class to encrypt/decrypt with the Vernam Cipher Algorithm, also 
 * One-Time-Pad. This is also known as "Perfect Cipher". The algorithm is same
 * as the Vigenere but a randomly key whose length is the same of the text is 
 * used and a key can be used only one time. Extended to all Unicode characters.
 * @author Eugenio Vinicio Berretta, Valdagno 23/10/2017
 */
public final class UnicodeVernamCipher implements Cipher {
    
    //FIELDS
    
    /**
     * The key of the cipher. It is a String long as the text, one-time-pad and
     * randomly generated.
     */
    private String lastKey;
    
    /**
     * The list containing all the used keys.
     */
    private ArrayList<String> usedKeys = new ArrayList<>();
    
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
     * Constructor of the class. The key is randomly chosen with the length of 
     * the text and one-time-pad, the text is encrypted. The result is saved in 
     * this.lastEncryptedText.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     */
    public UnicodeVernamCipher(String text) {
        this.encryptText(text);
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen with the length of 
     * the text and one-time-pad, the text is encrypted. The result is saved in 
     * this.lastEncryptedText.
     * @param usedKeys ArrayList(String): The list containing all used keys
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     */
    public UnicodeVernamCipher(ArrayList<String> usedKeys, String text) {
        this.usedKeys = usedKeys;
        this.encryptText(text);
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is checked, the text is decrypted. The 
     * result is saved in this.lastDecryptedText.
     * @param key String: The key that you want to use to decrypt the text. It
     * must have the same length of the text and not be used before
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public UnicodeVernamCipher(String key, String text) throws IllegalCipherKeyException {
        UnicodeVernamCipher.checkKey(key, this.usedKeys);
        this.lastKey = key;
        this.decryptText(text);
        this.lastEncryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is checked, the text is decrypted. The 
     * result is saved in this.lastDecryptedText.
     * @param usedKeys ArrayList(String): The list containing all used keys
     * @param key String: The key that you want to use to decrypt the text. It
     * must have the same length of the text and not be used before
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public UnicodeVernamCipher(ArrayList<String> usedKeys, String key, String text) throws IllegalCipherKeyException {
        UnicodeVernamCipher.checkKey(key, this.usedKeys);
        this.usedKeys = usedKeys;
        this.lastKey = key;
        this.decryptText(text);
        this.lastEncryptedText = "";
    }
    
    //GETTERS
    
    /**
     * Getter method of the field lastKey.
     * @return String: the class field lastKey
     */
    public String getLastKey() {
        return this.lastKey;
    }
    
    /**
     * Getter method of the field usedKeys.
     * @return ArrayList(String): the class field usedKeys
     */
    public ArrayList<String> getUsedKeys() {
        return this.usedKeys;
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
    
    //PUBLIC METHODS
    
    /**
     * This method adds the String ArrayList given to the field usedKeys.
     * @param usedKeys ArrayList(String): The strings that you want to add
     */
    public void addUsedKeys(ArrayList<String> usedKeys) {
        this.usedKeys.addAll(usedKeys);
    }
    
    /**
     * It returns the given text encrypted with a generated key. All characters
     * are encrypted. The result is also assigned to this.lastEncryptedText.
     * It adds the key generated to the list of the used keys.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty.
     * @return String: The encrypted text, an empty String if the text equals
     * null or is an empty String
     */
    @Override
    public String encryptText(String text) {
        if(text == null || text.isEmpty()) {
            this.lastEncryptedText = "";
            return "";
        }
        this.lastKey = UnicodeVernamCipher.generateRandomKey(text.length(), this.usedKeys);
        StringBuilder encryptedText = new StringBuilder();
        int keyLength = this.lastKey.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + this.lastKey.charAt(j) - 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        this.usedKeys.add(this.lastKey);
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with the this.lastKey key. All characters
     * are decrypted. The result is also assigned to this.lastDecryptedText.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty.
     * @return String: The decrypted text, an empty String if the text equals
     * null or is an empty String
     */
    @Override
    public String decryptText(String text) {
        if(text == null || text.isEmpty()) {
            this.lastDecryptedText = "";
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int keyLength = this.lastKey.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - this.lastKey.charAt(j) + 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    /**
     * It returns the given text decrypted with the given key. All characters
     * are decrypted. The result is also assigned to this.lastDecryptedText.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty.
     * @param key String: The key that you want to use to decrypt the text. It
     * must have the same length of the text and have never been used before
     * @return String: The decrypted text, an empty String if the text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public String decryptText(String text, String key) throws IllegalCipherKeyException {
        if(text == null || text.isEmpty()) {
            this.lastDecryptedText = "";
            return "";
        }
        UnicodeVernamCipher.checkKey(key, this.usedKeys);
        StringBuilder decryptedText = new StringBuilder();
        int keyLength = key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            decryptedText.append((char) (text.charAt(i) - key.charAt(j) + 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //PRIVATE STATIC METHODS
    
    /**
     * This method generate a random key.
     * @param length int: The length of the key
     * @param usedKeys ArrayList(String): The keys already used to encrypt.
     * @return String: The generated random key
     */
    private static String generateRandomKey(int length, ArrayList<String> usedKeys) {
        if(length < 1) {
            throw new IllegalArgumentException("The length must be positive");
        }
        StringBuilder key = new StringBuilder();
        do
        {
            for(int i = 0; i < length; i++) 
            {
                key.append((char) new Random().nextInt());
            }
        }
        while(usedKeys.contains(key.toString()));
        return key.toString();
    }
    
    /**
     * This method checks if the key is valid and throws an exception if it is 
     * not.
     * @param key String: The key that you want to check
     * @param usedKeys ArrayList(String): The list of the already used keys
     * @throws IllegalCipherKeyException If the key is not valid
     */
    static void checkKey(String key, ArrayList<String> usedKeys) throws IllegalCipherKeyException {
        if(key == null) {
            throw new IllegalCipherKeyException("The key can not be null");
        }
        if(usedKeys.contains(key)) {
            throw new IllegalCipherKeyException("The key has been already used");
        }
    }
    
    //PUBLIC STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key and the key used. 
     * All characters are encrypted.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty.
     * @param usedKeys ArrayList(String): The already used keys
     * @return String[]: The encrypted text and the key used, an empty String 
     * insetead of the text if the text equals null or is an empty String
     */
    public static String[] encryptText(String text, ArrayList<String> usedKeys) {
        if(text == null || text.isEmpty()) {
            return new String[]{ "", "" };
        }
        String key = UnicodeVernamCipher.generateRandomKey(text.length(), usedKeys);
        StringBuilder encryptedText = new StringBuilder();
        int keyLength = key.length();
        int textLength = text.length();
        for(int i = 0, j = 0; i < textLength; i++) 
        {
            encryptedText.append((char) (text.charAt(i) + key.charAt(j) - 'a'));
            j = (j == keyLength - 1) ? 0 : j + 1;
        }
        return new String[]{ encryptedText.toString(), key };
    }
    
    /**
     * It returns the given text decrypted with the given key. 
     * All characters are decrypted.
     * @param key String: The key that you want to use to decrypt the text. It
     * must have the same length of the text and have never been used
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty.
     * @param usedKeys ArrayList(String): The already used keys
     * @throws IllegalCipherKeyException: If the key have been already used
     * @return String: The decrypted text, an empty String if the text equals
     * null or is an empty String
     */
    public static String decryptText(String key, String text, ArrayList<String> usedKeys) throws IllegalCipherKeyException {
        if(text == null || text.isEmpty()) {
            return "";
        }
        UnicodeVernamCipher.checkKey(key, usedKeys);
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
