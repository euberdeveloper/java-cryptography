package cryptography;

import java.util.Random;

/**
 * The class to encrypt/decrypt with the classic Caesar Cipher Algorithm. Only 
 * letters are encrypted/decrypted.
 * @author Eugenio Vinicio Berretta, Valdagno 22/10/2017
 */
public final class CaesarCipher implements Cipher {
    
    //CONSTANT FIELDS
    
    /**
     * The constant byte field containing the alphabet letters number.
     */
    private static final byte ALPHABET_LENGTH = 26;
    
    //FIELDS
    
    /**
     * The key of the text. It can be any short, either negative or positive. If
     * it is zero then the text does not change after encryption. When a letter 
     * overbounds the end (or the begin) of the alphabet, it restarts to the
     * begin (or the end) of its. The alphabet is the english alphabet, either
     * positive or negative, any other character remains the same.
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
    public CaesarCipher() {
        this.key = this.generateRandomKey();
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted and the result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText. Only letters will be encrypted/decrypted. The key
     * will not be zero.
     * @param text String: The text that you want to encrypt. If it is 
     * null or empty then the encrypted text will be empty.
     */
    public CaesarCipher(String text) {
        this.key = this.generateRandomKey();
        this.encryptText(text);
        this.lastDecryptedText = "";  
    }
    
    /**
     * Constructor of the class. lastEncryptedText and lastDecryptedText become 
     * empty strings.
     * @param key short: The key of the cipher, any short is accepted. If it is 
     * zero then the encrypted/decrypted text is equal to the text.
     */
    public CaesarCipher(short key) {
        this.key = key;
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText. Only letters will be encrypted/decrypted.
     * @param key short: The key to encrypt/decrypt the text, any short is 
     * accepted. If it is zero then the encrypted/decrypted text is equal to the
     * text.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted/decrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     */
    public CaesarCipher(short key, String text, boolean encryption) {
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
     * Only letters will be decrypted/encrypted.
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
    
    //PRIVATE METHODS
    
    /**
     * This method generate a random key wich will not result the same text 
     * after encryption/decryption.
     * @return short: The generated random key
     */
    private short generateRandomKey() {
        short key;
        do
        {
            key = (short) new Random().nextInt();
        }
        while(key % CaesarCipher.ALPHABET_LENGTH == 0);
        return key;
    }
    
    //PUBLIC METHODS
    
    /**
     * It returns the given text encrypted with this.key key. Only letters are
     * encrypted, the others characters remain the same. The result is also 
     * assigned to this.lastEncryptedText.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty.
     * @return String: The encrypted text, an empty String if the text equals
     * null or is an empty String.
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
            char ch = text.charAt(i);
            if(this.key >= 0) {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    encryptedText.append((char) ('a' + ((ch - 'a' + this.key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    encryptedText.append((char) ('A' + ((ch - 'A' + this.key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else {
                    encryptedText.append(ch);
                }
            }
            else {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    encryptedText.append((char) ('a' + (CaesarCipher.ALPHABET_LENGTH + ch - 'a' + (this.key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    encryptedText.append((char) ('A' + (CaesarCipher.ALPHABET_LENGTH + ch - 'A' + (this.key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else {
                    encryptedText.append(ch);
                }
            }
        }
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with this.key key. Only letters are
     * decrypted, the others characters remain the same. The result is also 
     * assigned to this.lastDecryptedText.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty.
     * @return String: The decrypted text, an empty String if the text equals
     * null or is an empty String.
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
            char ch = text.charAt(i);
            if(this.key >= 0) {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    decryptedText.append((char) ('a' + (CaesarCipher.ALPHABET_LENGTH + ch - 'a' - (this.key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    decryptedText.append((char) ('A' + (CaesarCipher.ALPHABET_LENGTH + ch - 'A' - (this.key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else {
                    decryptedText.append(ch);
                }
            }
            else {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    decryptedText.append((char) ('a' + ((ch - 'a' - this.key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    decryptedText.append((char) ('A' + ((ch - 'A' - this.key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else {
                    decryptedText.append(ch);
                }
            }
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key. Only letters will
     * be encrypted.
     * @param key short: It can be any short value, either positive or negative,
     * if it is zero then the text does not change.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty. 
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
            char ch = text.charAt(i);
            if(key >= 0) {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    encryptedText.append((char) ('a' + ((ch - 'a' + key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    encryptedText.append((char) ('A' + ((ch - 'A' + key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else {
                    encryptedText.append(ch);
                }
            }
            else {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    encryptedText.append((char) ('a' + (CaesarCipher.ALPHABET_LENGTH + ch - 'a' + (key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    encryptedText.append((char) ('A' + (CaesarCipher.ALPHABET_LENGTH + ch - 'A' + (key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else {
                    encryptedText.append(ch);
                }
            }
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. Only letters will
     * be decrypted.
     * @param key short: It can be any short value, either positive or negative,
     * if it is zero then the text does not change.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty.
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
            char ch = text.charAt(i);
            if(key >= 0) {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    decryptedText.append((char) ('a' + (CaesarCipher.ALPHABET_LENGTH + ch - 'a' - (key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    decryptedText.append((char) ('A' + (CaesarCipher.ALPHABET_LENGTH + ch - 'A' - (key % CaesarCipher.ALPHABET_LENGTH)) % CaesarCipher.ALPHABET_LENGTH));
                }
                else {
                    decryptedText.append(ch);
                }
            }
            else {
                if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                    decryptedText.append((char) ('a' + ((ch - 'a' - key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                    decryptedText.append((char) ('A' + ((ch - 'A' - key) % CaesarCipher.ALPHABET_LENGTH)));
                }
                else {
                    decryptedText.append(ch);
                }
            }
        }
        return decryptedText.toString();
    }
    
}
