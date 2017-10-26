package cryptography;

/**
 * The class containing some static methods on ASCII characters
 * @author Eugenio Vinicio Berretta, Valdagno 24/10/2017
 */
public class Cryptography {

    public static void main(String[] args) throws IllegalCipherKeyException {
        PlayfairCipher cipher = new PlayfairCipher(null,"Ciaocomevafuckyoubitch", true);
        System.out.println(cipher.getKey());
        System.out.println(cipher.getLastEncryptedText());
        System.out.println(cipher.decryptText(cipher.getLastEncryptedText()));
    }
    
}
