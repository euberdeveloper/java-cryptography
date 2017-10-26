package cryptography;

import java.util.Random;

/**
 * The class to encrypt/decrypt with the Transposition Cipher Algorithm. It
 * works with all Unicode characters.
 * @author Eugenio Vinicio Berretta, Valdagno 24/10/2017
 */
public final class TranspositionCipher implements Cipher {
    
    //CONSTANT FIELDS
    
    /**
     * The constant byte containing the number of the alphabet letters.
     */
    public static final byte ALPHABET_LENGTH = 26;
    
    //FIELDS
    
    /**
     * The key of the text. The key must be positive. If the key is equal to one
     * or larger than the text length, the text does not change after encryption
     * or decription.
     */
    private int key;
    
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
     * Constructor of the class. The key is randomly chosen (Number between 1
     * and 21). lastEncryptedText and lastDecryptedText become empty strings.
     */
    public TranspositionCipher() {
        this.key = new Random().nextInt(20) + 1;
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted. The result is saved in this.lastEncryptedText.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     */
    public TranspositionCipher(String text) {
        this.key = new Random().nextInt(20) + 1;
        this.encryptText(text);
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. lastEncryptedText and lastDecryptedText become 
     * empty strings.
     * @param key int: The key of the text. It must be positive.
     * @throws IllegalCipherKeyException If the key is not positive
     */
    public TranspositionCipher(int key) throws IllegalCipherKeyException {
        if(key < 1) {
            throw new IllegalCipherKeyException("The key must be positive");
        }
        this.key = key;
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText.
     * @param key int: The key to encrypt/decrypt the text. It must be positive
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted/decrypted text will be empty
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     * @throws IllegalCipherKeyException If the key is not positive
     */
    public TranspositionCipher(int key, String text, boolean encryption) throws IllegalCipherKeyException {
        if(key < 1) {
            throw new IllegalCipherKeyException("The key must be positive");
        }
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
     * @return int: the class field key
     */
    public int getKey() {
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
     * @param key int: The new value of the key class field.
     * @throws IllegalCipherKeyException If the key is not positive
     */
    public void setKey(int key) throws IllegalCipherKeyException {
        if(key < 1) {
            throw new IllegalCipherKeyException("The key must be positive");
        }
        this.key = key;
    }
    
    /**
     * Setter method of the field key. It does also an encryption/decryption.
     * @param key int: The new value of the key class field.
     * @param text String: The text to encrypt/decrypt
     * @param encryption boolean: True if you want to encrypt, false if you 
     * want to decrypt
     * @throws IllegalCipherKeyException If the key is not positive
     */
    public void setKey(int key, String text, boolean encryption) throws IllegalCipherKeyException {
        if(key < 1) {
            throw new IllegalCipherKeyException("The key must be positive");
        }
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
     * It returns the given text encrypted with this.key key. Only letters are
     * encrypted, the others characters remain the same. The result is also 
     * assigned to this.lastEncryptedText.
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
        int nRow;
        if(text.length() >= this.key) {
            nRow = text.length() / this.key;
            nRow = (text.length() % this.key == 0) ? nRow : nRow + 1;
        }
        else {
            nRow = 1;
        }
        char[][] table = new char[nRow][this.key];
        int i, j, k = 0;
        for(i = 0; i < nRow && k < text.length(); i++) 
        {
            for(j = 0; j < this.key && k < text.length(); j++, k++)
            {
                table[i][j] = text.charAt(k);
            }
        }
        for(i = 0; i < this.key; i++)
        {
            for(j = 0; j < nRow; j++)
            {
                if(table[j][i] != 0) {
                    encryptedText.append(table[j][i]);
                }
            }
        }
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with the this.key key. Only letters are
     * decrypted, the others characters remain the same. The result is also 
     * assigned to this.lastDecryptedText.
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
        int nCol;
        if(text.length() >= this.key) {
            nCol = text.length() / this.key;
            nCol = (text.length() % this.key == 0) ? nCol : nCol + 1;
        }
        else {
            nCol = 1;
        }
        char[][] table = new char[this.key][nCol];
        int i, j, k = 0;
        for(i = 0; i < this.key && k < text.length(); i++) 
        {
            for(j = 0; j < ((this.key - i <= ((nCol * this.key) - text.length())) ? nCol - 1 : nCol) && k < text.length(); j++, k++)
            {
                table[i][j] = text.charAt(k);
            }
        }
        for(i = 0; i < nCol; i++)
        {
            for(j = 0; j < this.key; j++)
            {
                if(table[j][i] != 0) {
                    decryptedText.append(table[j][i]);
                }
            }
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key. All characters
     * are encrypted.
     * @param key int: It can be any int value, either positive or negative, if
     * it is zero then the text does not change.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty then the encrypted text will be empty
     * @return String: The encrypted text, an empty String in case text equals
     * null or is an empty String
     */
    public static String encryptText(int key, String text) {
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        int nRow;
        if(text.length() >= key) {
            nRow = text.length() / key;
            nRow = (text.length() % key == 0) ? nRow : nRow + 1;
        }
        else {
            nRow = 1;
        }
        char[][] table = new char[nRow][key];
        int i, j, k = 0;
        for(i = 0; i < nRow && k < text.length(); i++) 
        {
            for(j = 0; j < key && k < text.length(); j++, k++)
            {
                table[i][j] = text.charAt(k);
            }
        }
        for(i = 0; i < key; i++)
        {
            for(j = 0; j < nRow; j++)
            {
                if(table[j][i] != 0) {
                    encryptedText.append(table[j][i]);
                }
            }
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. All characters
     * are decrypted.
     * @param key int: It can be any int value, either positive or negative, if
     * it is zero then the text does not change.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     */
    public static String decryptText(int key, String text) {
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int nCol;
        if(text.length() >= key) {
            nCol = text.length() / key;
            nCol = (text.length() % key == 0) ? nCol : nCol + 1;
        }
        else {
            nCol = 1;
        }
        char[][] table = new char[key][nCol];
        int i, j, k = 0;
        for(i = 0; i < key && k < text.length(); i++) 
        {
            for(j = 0; j < ((key - i <= ((nCol * key) - text.length())) ? nCol - 1 : nCol) && k < text.length(); j++, k++)
            {
                table[i][j] = text.charAt(k);
            }
        }
        for(i = 0; i < nCol; i++)
        {
            for(j = 0; j < key; j++)
            {
                if(table[j][i] != 0) {
                    decryptedText.append(table[j][i]);
                }
            }
        }
        return decryptedText.toString();
    }
    
}
