package cryptography;

import java.util.Arrays;
import java.util.Random;

/**
 * The class to encrypt/decrypt with the Playfair Cipher Algorithm. The key can
 * be as long as you want but can contain only letters. The text can contain 
 * only letters. J is substituted with I and if the text length is not
 * equal, then letter zed is added.
 * @author Eugenio Vinicio Berretta, Valdagno 23/10/2017
 */
public final class PlayfairCipher implements Cipher {
    
    //FIELDS
    
    /**
     * The key of the text. It can be as long as you want, but only letters 
     * are allowed.
     */
    private String key;
    
    /**
     * The table whose values depends on the key and wich is used by the 
     * algorithm.
     */
    private char[][] table = new char[5][5];
    
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
    public PlayfairCipher() {
        this.key = this.generateRandomKey();
        this.table = PlayfairCipher.fillTable(this.key);
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The key is randomly chosen, the text is
     * encrypted or decrypted, depending on the given boolean. The result is 
     * saved in this.lastEncryptedText or this.lastDecryptedText.
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty or does not contain only letters then the encrypted text 
     * will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     */
    public PlayfairCipher(String text, boolean encryption) {
        this.key = this.generateRandomKey();
        this.table = PlayfairCipher.fillTable(this.key); 
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
     * @param key String: The key of the text, only letters allowed.
     * @throws IllegalCipherKeyException If the key is not valid.
     */
    public PlayfairCipher(String key) throws IllegalCipherKeyException {
        this.key = key;
        PlayfairCipher.checkKey(key);
        this.table = PlayfairCipher.fillTable(key);
        this.lastEncryptedText = "";
        this.lastDecryptedText = "";
    }
    
    /**
     * Constructor of the class. The text is encrypted or decrypted, depending 
     * on the given boolean. The result is saved in this.lastEncryptedText or 
     * this.lastDecryptedText.
     * @param key String: The key to encrypt/decrypt the text. Only letters 
     * allowed
     * @param text String: The text that you want to encrypt/decrypt. If it is 
     * null or empty or does not contain only letters then the encrypted text 
     * will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you want
     * to decrypt
     * @throws IllegalCipherKeyException If the key is not valid.
     */
    public PlayfairCipher(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        this.key = key;
        PlayfairCipher.checkKey(key);
        this.table = PlayfairCipher.fillTable(key);
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
     * @param key String: The new value of the key class field. Only letters are
     * allowed.
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public void setKey(String key) throws IllegalCipherKeyException {
        this.key = key;
        PlayfairCipher.checkKey(key);
        this.table = PlayfairCipher.fillTable(key);
    }
    
    /**
     * Setter method of the field key. It does also an encryption/decryption.
     * @param key String: The new value of the key class field. Only letters are
     * allowed.
     * @param text String: The text to encrypt/decrypt. If it is null or empty 
     * or does not contain only letters then the encrypted text will be empty.
     * @param encryption boolean: True if you want to encrypt, false if you 
     * want to decrypt
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public void setKey(String key, String text, boolean encryption) throws IllegalCipherKeyException {
        this.key = key;
        PlayfairCipher.checkKey(key);
        this.table = PlayfairCipher.fillTable(key);
        if(encryption) {
            this.encryptText(text);
        }
        else {
            this.decryptText(text);
        }
    }
    
    //PRIVATE METHODS
    
    /**
     * This method returns a random valid key.
     * @return String: The key generated.
     */
    private String generateRandomKey() {
        char[] key = "ABCDEFGHIKLMNOPQRSTUVWXYZ".toCharArray();
        char temp;
        int first, second;
        for(int i = 0; i < 50; i++)
        {
            first = new Random().nextInt(25);
            second = new Random().nextInt(25);
            temp = key[first];
            key[first] = key[second];
            key[second] = temp;
        }
        return new String(key);
    }   
    
    //PUBLIC METHODS
    
    /**
     * It returns the given text encrypted with this.key key. All letters
     * are encrypted. The result is also assigned to this.lastEncryptedText.
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty or does not contain only letters then the encrypted text will be 
     * empty.
     * @return String: The encrypted text, an empty String if the text equals
     * null or is an empty String
     */
    @Override
    public String encryptText(String text) {
        if(text == null || text.isEmpty() || !PlayfairCipher.checkText(text)) {
            this.lastEncryptedText = "";
            return "";
        }
        StringBuilder encryptedText = new StringBuilder();
        text = text.replace('J', 'I');
        text = text.replace('j', 'i');
        int length = text.length();
        for(int i = 0; i < length; i += 2)
        {
            if(i + 1 == length) {
                encryptedText.append(PlayfairCipher.encryptPair(text.charAt(i), 'Z', this.table));
            }
            else {
                encryptedText.append(PlayfairCipher.encryptPair(text.charAt(i), text.charAt(i + 1), this.table));
            }
        }
        this.lastEncryptedText = encryptedText.toString();
        return this.lastEncryptedText;
    }
    
    /**
     * It returns the given text decrypted with the this.key key. All letters
     * are decrypted. The result is also assigned to this.lastDecryptedText.
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty or does not contain only letters then the encrypted text will be 
     * empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     */
    @Override
    public String decryptText(String text) {
        if(text == null || text.isEmpty() || !PlayfairCipher.checkText(text)) {
            this.lastDecryptedText = "";
            return "";
        }
        StringBuilder decryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i += 2)
        {
            decryptedText.append(PlayfairCipher.decryptPair(text.charAt(i), text.charAt(i + 1), this.table));
        }
        this.lastDecryptedText = decryptedText.toString();
        return this.lastDecryptedText;
    }
    
    //PRIVATE STATIC METHODS
    
     /**
     * This method checks if the key is valid. If not, it throws an exception.
     * @param key String: The key that you want to check
     * @throws IllegalCipherKeyException If the key is not valid
     */
    private static void checkKey(String key) throws IllegalCipherKeyException {
        if(key == null) {
            throw new IllegalCipherKeyException();
        }
        int length = key.length();
        for(int i = 0; i < length; i++) 
        {
            if(!ASCIICharacterUtils.isLetter(key.charAt(i))) {
                throw new IllegalCipherKeyException();
            }
        }
    }
    
    /**
     * This method checks if the text contains only letters.
     * @param text String: The text that you want to check
     * @return boolean: True if the text is valid, false if it is not
     */
    private static boolean checkText(String text) {
        int length = text.length();
        for(int i = 0; i < length; i++)
        {
            if(!ASCIICharacterUtils.isLetter(text.charAt(i))) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * This method fills the table with the right characters depending on the
     * key.
     * @param key String: The key to fill the table
     * @return char[][]: The filled table
     */
    private static char[][] fillTable(String key) {
        char[][] table = new char[5][5];
        key = key.toUpperCase();
        boolean[] unused = new boolean[26];
        Arrays.fill(unused, true);
        unused['J' - 'A'] = false;
        int row = 0, col = 0, length = key.length();
        for(int i = 0; (i < length) && (row < 5); i++)
        {
            if(unused[key.charAt(i) - 'A']) {
                table[row][col] = key.charAt(i);
                unused[key.charAt(i) - 'A'] = false;
                if(col == 4) {
                    col = 0; 
                    row++;
                }
                else {
                    col++;
                }
            }
        }
        if(row < 5) {
            for(int i = 0; i < 26 && row < 5; i++) {
                if(unused[i]) {
                    table[row][col] = (char) ('A' + i);
                    unused[i] = false;
                    if(col == 4) {
                        col = 0; 
                        row++;
                    }
                    else {
                        col++;
                    }
                }
            }
        }
        return table;
    }
    
    /**
     * This method returns an array with the position { row, col } of the given
     * character in the cipher table.
     * @param ch char: The character that you want to find
     * @param table char[][]: The table given by the key
     * @return int[]: The position { row, col } of the character
     */
    private static int[] findPositionInTable(char ch, char[][] table) {
        int i, j;
        for(i = 0; i < 5; i++) 
        {
            for(j = 0; j < 5; j++)
            {
                if(table[i][j] == ch) {
                    return new int[]{ i, j };
                }
            }
        }
        return new int[]{ -1, -1 };
    }
    
    /**
     * This method encrypts a pair of characters.
     * @param first char: The first character of the pair
     * @param second char: The second character of the pair
     * @param table char[][]: The table given by the key
     * @return String: The encrypted pair as a String
     */
    private static String encryptPair(char first, char second, char[][] table) {
        int[] firstPosition =  PlayfairCipher.findPositionInTable(Character.toUpperCase(first), table);
        int[] secondPosition =  PlayfairCipher.findPositionInTable(Character.toUpperCase(second), table);
        if(firstPosition[0] == secondPosition[0])
        {
            int row = firstPosition[0], firstCol, secondCol;
            firstCol = (firstPosition[1] == 4) ? 0 : firstPosition[1] + 1;
            secondCol = (secondPosition[1] == 4) ? 0 : secondPosition[1] + 1;
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[row][firstCol] : Character.toLowerCase(table[row][firstCol]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[row][secondCol] : Character.toLowerCase(table[row][secondCol]);
            return x + "" + y;
        }
        else if(firstPosition[1] == secondPosition[1]) {
            int col = firstPosition[1], firstRow, secondRow;
            firstRow = (firstPosition[0] == 4) ? 0 : firstPosition[0] + 1;
            secondRow = (secondPosition[0] == 4) ? 0 : secondPosition[0] + 1;
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[firstRow][col] : Character.toLowerCase(table[firstRow][col]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[secondRow][col] : Character.toLowerCase(table[secondRow][col]);
            return x + "" + y;
        }
        else {
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[firstPosition[0]][secondPosition[1]] : Character.toLowerCase(table[firstPosition[0]][secondPosition[1]]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[secondPosition[0]][firstPosition[1]] : Character.toLowerCase(table[secondPosition[0]][firstPosition[1]]);
            return x + "" + y;        
        }
    }
    
    /**
     * This method decrypts a pair of characters.
     * @param first char: The first character of the pair
     * @param second char: The second character of the pair
     * @param table char[][]: The table given by the key
     * @return String: The decrypted pair as a String
     */
    private static String decryptPair(char first, char second, char[][] table) {
        int[] firstPosition =  PlayfairCipher.findPositionInTable(Character.toUpperCase(first), table);
        int[] secondPosition =  PlayfairCipher.findPositionInTable(Character.toUpperCase(second), table);
        if(firstPosition[0] == secondPosition[0])
        {
            int row = firstPosition[0], firstCol, secondCol;
            firstCol = (firstPosition[1] == 0) ? 4 : firstPosition[1] - 1;
            secondCol = (secondPosition[1] == 0) ? 4 : secondPosition[1] - 1;
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[row][firstCol] : Character.toLowerCase(table[row][firstCol]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[row][secondCol] : Character.toLowerCase(table[row][secondCol]);
            return x + "" + y;
        }
        else if(firstPosition[1] == secondPosition[1]) {
            int col = firstPosition[1], firstRow, secondRow;
            firstRow = (firstPosition[0] == 0) ? 4 : firstPosition[0] - 1;
            secondRow = (secondPosition[0] == 0) ? 4 : secondPosition[0] - 1;
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[firstRow][col] : Character.toLowerCase(table[firstRow][col]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[secondRow][col] : Character.toLowerCase(table[secondRow][col]);
            return x + "" + y;
        }
        else {
            char x = (ASCIICharacterUtils.isUppercaseLetter(first)) ? table[firstPosition[0]][secondPosition[1]] : Character.toLowerCase(table[firstPosition[0]][secondPosition[1]]);
            char y = (ASCIICharacterUtils.isUppercaseLetter(second)) ? table[secondPosition[0]][firstPosition[1]] : Character.toLowerCase(table[secondPosition[0]][firstPosition[1]]);
            return x + "" + y;        
        }
    }
    
    //PUBLIC STATIC METHODS
    
    /**
     * It returns the given text encrypted with the given key. All letters
     * are encrypted.
     * @param key String: The key that you want to use. 
     * It can contain only letters
     * @param text String: The text that you want to encrypt. If it is null or 
     * empty or does not contain only letters then the encrypted text will be 
     * empty
     * @return String: The encrypted text, an empty String in case text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public static String encryptText(String key, String text) throws IllegalCipherKeyException {
        if(text == null || text.isEmpty() || !PlayfairCipher.checkText(text)) {
            return "";
        }
        PlayfairCipher.checkKey(key);
        char[][] table = PlayfairCipher.fillTable(key);
        StringBuilder encryptedText = new StringBuilder();
        text = text.replace('J', 'I');
        text = text.replace('j', 'i');
        int length = text.length();
        for(int i = 0; i < length; i += 2)
        {
            if(i + 1 == length) {
                encryptedText.append(PlayfairCipher.encryptPair(text.charAt(i), 'Z', table));
            }
            else {
                encryptedText.append(PlayfairCipher.encryptPair(text.charAt(i), text.charAt(i + 1), table));
            }
        }
        return encryptedText.toString();
    }
    
    /**
     * It returns the given text decrypted with the given key. All letters
     * are decrypted.
     * @param key String: The key that you want to use. It can contain only 
     * letters
     * @param text String: The text that you want to decrypt. If it is null or 
     * empty or does not contain only letters then the encrypted text will be 
     * empty
     * @return String: The decrypted text, an empty String in case text equals
     * null or is an empty String
     * @throws IllegalCipherKeyException If the key is not valid
     */
    public static String decryptText(String key, String text) throws IllegalCipherKeyException {
        if(text == null || text.isEmpty() || !PlayfairCipher.checkText(text)) {
            return "";
        }
        PlayfairCipher.checkKey(key);
        char[][] table = PlayfairCipher.fillTable(key);
        StringBuilder decryptedText = new StringBuilder();
        int length = text.length();
        for(int i = 0; i < length; i += 2)
        {
            decryptedText.append(PlayfairCipher.decryptPair(text.charAt(i), text.charAt(i + 1), table));
        }
        return decryptedText.toString();
    }
    
}

