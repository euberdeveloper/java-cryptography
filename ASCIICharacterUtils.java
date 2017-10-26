package cryptography;

/**
 * The class containing some static methods on ASCII characters
 * @author Eugenio Vinicio Berretta, Valdagno 24/10/2017
 */
class ASCIICharacterUtils {
    
    /**
     * This method checks if the given char is an uppercase ASCII letter.
     * @param ch char: The character that you want to check
     * @return boolean: True if the given char is an uppercase ASCII letter, 
     * false otherwise
     */
    static boolean isUppercaseLetter(char ch) {
        return (ch >= 65 && ch <= 90);
    }
    
    /**
     * This method checks if the given char is a lowercase ASCII letter.
     * @param ch char: The character that you want to check
     * @return boolean: True if the given char is a lowercase ASCII letter, 
     * false otherwise
     */
    static boolean isLowercaseLetter(char ch) {
        return (ch >= 97 && ch <= 122);
    }
    
    /**
     * This method checks if the given char is an ASCII letter.
     * @param ch char: The character that you want to check
     * @return boolean: True if the given char is an letter, false otherwise
     */
    static boolean isLetter(char ch) {
        return (ASCIICharacterUtils.isUppercaseLetter(ch) || ASCIICharacterUtils.isLowercaseLetter(ch));
    }
    
}
