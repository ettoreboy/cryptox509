package cryptox509;

import java.io.Console;
import java.util.Arrays;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class Utilities {
     /**
     * *
     * Encode to hex a byte array
     *
     * @param input- the byte array to be parsed
     * @return the resulting String
     */
    public static String toHex(byte[] input) {
        if (input == null || input.length == 0) {
            return "";
        }

        int inputLength = input.length;
        StringBuilder output = new StringBuilder(inputLength * 2);

        for (int i = 0; i < inputLength; i++) {
            int next = input[i] & 0xff;
            if (next < 0x10) {
                output.append("0");
            }

            output.append(Integer.toHexString(next));
        }

        return output.toString();
    }
    
     /**
     * *
     * Check owner password two times
     *
     * @return
     */
    public static char[] checkOwnerPassword() {
        Console console = System.console();
        System.out.println("Enter key encryption password:");
        char[] input = console.readPassword();
        System.out.println("Enter password again:");
        if (Arrays.equals(input, console.readPassword())) {
            return input;
        }

        System.err.println("Passwords do not match!");
        System.exit(1);
        return null;
    }

    
}
