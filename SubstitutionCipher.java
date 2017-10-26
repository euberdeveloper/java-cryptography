package cryptography;

import java.util.Random;

/**
 * The class to encrypt/decrypt with the Substitution Cipher. In the key you 
 * have to write all the letters of the alphabet in the order that you want. 
 * Every letter has to be written in the key only once. You can choose if write 
 * the letters all in lowercase or all in uppercase. Then the first letter will
 * replace A, the second B, and this for all the alphabet letter.
 * @author Eugenio Vinicio Berretta, Valdagno 22/10/2017
 */
public final class SubstitutionCipher implements Cipher {
    
    //CONSTANT FIELDS
    
    /**
     * The constant byte field containing the alphabet letter number.
     */
    private static final byte ALPHABET_LENGTH = 26;
    
    /**
     * The constant String field containing the alphabet in uppercase and in lowercase.
     */
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    
    //FIELDS
    
    /**
     * The key of the cipher. You have to write all the letters of the alphabet
     * in the order that you want. Every letter has to be written in the key
     * only once. You can choose if write the letters all in lowercase or all in
     * uppercase.
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
    public SubstitutionCipher() {
        this.key = SubstitutionCipher.generateRandomKey();
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted or decrypted, depending on the given boolean. The result is 
     * saved in this.lastEncryptedText or this.lastDecryptedText.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     */
    public SubstitutionCipher(String text, boolean encryption) {
        this.key = SubstitutionCipher.generateRandomKey();
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
     * Constructor of the class. lastEncryptedText and lastDecryptedText become 
     * empty strings.
     * @param key String: The key of the cipher. You have to write all the 
     * letters of the alphabet in the order that you want. Every letter has to 
     * be written in the key only once. You can choose if write the letters all 
     * in lowercase or all in uppercase. 
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public SubstitutionCipher(String key) throws IllegalCipherKeyException {
        this.key = SubstitutionCipher.completeKey(key);
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText.
     * @param key String: The key of the cipher. You have to write all the 
     * letters of the alphabet in the order that you want. Every letter has to 
     * be written in the key only once. You can choose if write the letters all 
     * in lowercase or all in uppercase.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty then the encrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public SubstitutionCipher(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        this.key = SubstitutionCipher.completeKey(key);
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
     * @param key String: The new key of the cipher. You have to write all the 
     * letters of the alphabet in the order that you want. Every letter has to 
     * be written in the key only once. You can choose if write the letters all 
     * in lowercase or all in uppercase. 
     * @throws IllegalCipherKeyException: If the key is not valid
     */
    public void setKey(String key) throws IllegalCipherKeyException {
        this.key = SubstitutionCipher.completeKey(key);
    }
    
    /**
     * Setter method of the field key. It does also an encryption/decryption.
     * @param key String: The new key of the cipher. You have to write all the 
     * letters of the alphabet in the order that you want. Every letter has to 
     * be written in the key only once. You can choose if write the letters all 
     * in lowercase or all in uppercase. 
     * @param text String: The text to encrypt/decrypt. If it is null or empty 
     * then the encrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you 
     * want to decrypt
     * @throws IllegalCipherKeyException: If the key is not valid
     */
    public void setKey(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        this.key = SubstitutionCipher.completeKey(key);
        if(encryption) {
            this.encryptText(text);
        }
        else {
            this.decryptText(text);
        }
    }
    
    //PUBLIC METHODS
    
    /**
     * It returns the given text encrypted with this.key key. Only letters will
     * be encrypted. The result is also assigned to this.lastEncryptedText.
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
        int index;
        char ch;
        for(int i = 0; i < text.length(); i++) 
        {
            index = SubstitutionCipher.ALPHABET.indexOf(text.charAt(i));
            if(index != -1) {
                encryptedText.append(this.key.charAt(index));
            }
            else {
                encryptedText.append(text.charAt(i));
            }
        }
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with the this.key key. Only letters
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
        int index;
        for(int i = 0; i < text.length(); i++) 
        {
            index = this.key.indexOf(text.charAt(i));
            if(index != -1) {
                decryptedText.append(SubstitutionCipher.ALPHABET.charAt(index));
            }
            else {
                decryptedText.append(text.charAt(i));
            }
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //PRIVATE STATIC METHODS
    
    /**
     * This method returns true if there are two associated letters between the
     * key and the alphabet, false otherwise.
     * @param key String: The key that you want to check
     * @return boolean: True if there are two associated letters between the key
     * and the alphabet, false otherwise.
     */
    private static boolean checkRipetition(char[] key) {
        for(int i = 0; i < SubstitutionCipher.ALPHABET_LENGTH; i++)
        {
            if(key[i] == SubstitutionCipher.ALPHABET.charAt(i)) {
                return true;
            }
        }
        return false;
    }
    
    //PUBLIC STATIC METHODS
    
    /**
     * This method generates a random valid key.
     * @return String: The key generated
     */
    @SuppressWarnings("empty-statement")
    public static String generateRandomKey() {
        char[] key = SubstitutionCipher.ALPHABET.substring(0, SubstitutionCipher.ALPHABET_LENGTH).toCharArray();
        int first, second;
        char temp;
        do
        {
            first = new Random().nextInt(SubstitutionCipher.ALPHABET_LENGTH);
            second = new Random().nextInt(SubstitutionCipher.ALPHABET_LENGTH);
            temp = key[second];
            key[second] = key[first];
            key[first] = temp;
        }
        while(SubstitutionCipher.checkRipetition(key));
        String skey = new String(key);
        try { skey = SubstitutionCipher.completeKey(skey); } catch(IllegalCipherKeyException ex) {};
        return skey;
    }
    
    /**
     * This method completes the key by adding the uppercase part if the key is
     * lowercase or by adding the lowercase part if the key is uppercase.
     * @param key String: The key that you want to complete
     * @return String: The key completed, null if the key is not valid.
     * @throws IllegalCipherKeyException: If the key is not valid
     */
    public static String completeKey(String key) throws IllegalCipherKeyException {
        if(!SubstitutionCipher.checkKey(key)) {
            throw new IllegalCipherKeyException();
        } 
        if(ASCIICharacterUtils.isUppercaseLetter(key.charAt(0))) {
            return key + key.toLowerCase();
        }
        else if(ASCIICharacterUtils.isLowercaseLetter(key.charAt(0))) {
            return key.toUpperCase() + key;
        }
        else {
            return null;
        }
    }
    
    /**
     * This method checks if the key is valid.
     * @param key String: The key that you want to check
     * @return boolean: True if the key is valid, false otherwise
     */
    public static boolean checkKey(String key) {
        if(key == null) {
            return false;
        }
        int cont, i, j;
        char ch;
        if(key.length() == SubstitutionCipher.ALPHABET_LENGTH) {
            if(ASCIICharacterUtils.isUppercaseLetter(key.charAt(0))) {
                for(i = 0; i < SubstitutionCipher.ALPHABET_LENGTH; i++)
                {
                    ch = SubstitutionCipher.ALPHABET.charAt(i);
                    if(ASCIICharacterUtils.isUppercaseLetter(ch)) {
                        cont = 0;
                        for(j = 0; j < key.length(); j++)
                        {
                            if(ch == key.charAt(j)) {
                                cont++;
                            }
                        }
                        if(cont != 1) {
                            return false;
                        }
                    }
                }
            }
            else if(ASCIICharacterUtils.isLowercaseLetter(key.charAt(0))) {
                for(i = 0; i < SubstitutionCipher.ALPHABET_LENGTH; i++)
                {
                    ch = SubstitutionCipher.ALPHABET.charAt(i);
                    if(ASCIICharacterUtils.isLowercaseLetter(ch)) {
                        cont = 0;
                        for(j = 0; j < key.length(); j++)
                        {
                            if(ch == key.charAt(j)) {
                                cont++;
                            }
                        }
                        if(cont != 1) {
                            return false;
                        }
                    }
                }
            }
            else {
                return false;
            }
        } 
        else {
            return false;
        }
        return true;
    }
    
    /**
     * It returns the given text encrypted with the given key. Only letters will
     * be encrypted.
     * @param key String: The key to encrypt the text
     * @param text String: The text that you want to encrypt
     * @return String: The encrypted text. If it is null or empty then the 
     * encrypted text will be empty. 
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public static String encryptText(String key, String text) throws IllegalCipherKeyException {
        key = SubstitutionCipher.completeKey(key);
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        int index;
        char ch;
        for(int i = 0; i < text.length(); i++) 
        {
            index = SubstitutionCipher.ALPHABET.indexOf(text.charAt(i));
            if(index != -1) {
                encryptedText.append(key.charAt(index));
            }
            else {
                encryptedText.append(text.charAt(i));
            }
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. Only letters will
     * be decrypted.
     * @param key String: The key to decrypt the text
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty then the decrypted text will be empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public static String decryptText(String key, String text) throws IllegalCipherKeyException {
        key = SubstitutionCipher.completeKey(key);
        if(text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int index;
        for(int i = 0; i < text.length(); i++) 
        {
            index = key.indexOf(text.charAt(i));
            if(index != -1) {
                decryptedText.append(SubstitutionCipher.ALPHABET.charAt(index));
            }
            else {
                decryptedText.append(text.charAt(i));
            }
        }
        return decryptedText.toString();
    }
    
}
