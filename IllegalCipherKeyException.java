package cryptography;

/**
 * Class of the Exception thrown in case the given key to a cipher class is not
 * valid.
 * @author Eugenio Vinicio Berretta 22/10/2017
 */
public class IllegalCipherKeyException extends Exception {

    /**
     * Constructor of the class, with a default message.
     */
    public IllegalCipherKeyException() {
        super("Illegal key argument given to the cipher");
    }
    
    /**
     * Constructor of the class.
     * @param message String: The message of the exception
     */
    public IllegalCipherKeyException(String message) {
        super(message);
    }
    
    
}

