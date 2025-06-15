// Mousa Mohamed Mousa Mohamed Hussein 20235042
// Mohamed Hossam Elsayed 20236083


import java.util.Scanner;

public class AESsimple {

    private static final int Nb = 4; // Number of columns (4x4 state)
    private static final int Nk = 4; // Key size (128 bits / 32 bits = 4 words)
    private static final int Nr = 10; // Number of rounds for AESsimple-128

    // S-box and inverse S-box
    private static final int[] sbox = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
        0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
        0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
        0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
        0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
        0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
        0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
        0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
        0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
        0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
        0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
        0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
        0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
        0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
        0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
        0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };

    private static final int[] invSbox = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
        0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
        0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
        0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
        0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
        0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
        0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
        0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
        0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
        0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
        0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
        0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
        0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
        0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
        0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
        0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };

    // Rcon table
    private static final int[] Rcon = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        // Get user input
        System.out.print("Enter message to encrypt (16 characters): ");
        String plaintext = scanner.nextLine();
        
        System.out.print("Enter encryption key (16 characters): ");
        String key = scanner.nextLine();
        
        // Pad inputs if necessary
        plaintext = padString(plaintext);
        key = padString(key);
        
        byte[] input = plaintext.getBytes();
        byte[] keyBytes = key.getBytes();

        // Encrypt
        byte[] encrypted = encrypt(input, keyBytes);
        System.out.print("Encrypted: ");
        for (byte b : encrypted) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // Decrypt
        byte[] decrypted = decrypt(encrypted, keyBytes);
        System.out.println("Decrypted: " + new String(decrypted).trim());
        
        scanner.close();
    }
    
    private static String padString(String input) {
        // Pad with spaces if shorter than 16 characters
        if (input.length() < 16) {
            return String.format("%-16s", input);
        }
        // Truncate if longer than 16 characters
        else if (input.length() > 16) {
            return input.substring(0, 16);
        }
        return input;
    }

    public static byte[][] toState(byte[] input) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = input[i];
        }
        return state;
    }

    public static byte[] fromState(byte[][] state) {
        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++) {
            output[i] = state[i % 4][i / 4];
        }
        return output;
    }

    public static void subBytes(byte[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = (byte) (sbox[state[row][col] & 0xFF]);
            }
        }
    }

    public static void invSubBytes(byte[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] = (byte) (invSbox[state[row][col] & 0xFF]);
            }
        }
    }

    public static void shiftRows(byte[][] state) {
        // Rotate first row 1 columns to left
        byte temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        // Rotate second row 2 columns to left
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Rotate third row 3 columns to left
        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
    }

    public static void invShiftRows(byte[][] state) {
        // Rotate first row 1 columns to right
        byte temp = state[1][3];
        state[1][3] = state[1][2];
        state[1][2] = state[1][1];
        state[1][1] = state[1][0];
        state[1][0] = temp;

        // Rotate second row 2 columns to right
        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        // Rotate third row 3 columns to right
        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    public static byte gmul(byte a, byte b) {
        byte p = 0;
        for (int counter = 0; counter < 8; counter++) {
            if ((b & 1) != 0)
                p ^= a;
            boolean hiBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (hiBitSet)
                a ^= 0x1B; // Rijndael's irreducible polynomial
            b >>= 1;
        }
        return p;
    }

    public static void mixColumns(byte[][] state) {
        for (int col = 0; col < 4; col++) {
            byte a0 = state[0][col];
            byte a1 = state[1][col];
            byte a2 = state[2][col];
            byte a3 = state[3][col];

            state[0][col] = (byte) (gmul((byte) 0x02, a0) ^ gmul((byte) 0x03, a1) ^ a2 ^ a3);
            state[1][col] = (byte) (a0 ^ gmul((byte) 0x02, a1) ^ gmul((byte) 0x03, a2) ^ a3);
            state[2][col] = (byte) (a0 ^ a1 ^ gmul((byte) 0x02, a2) ^ gmul((byte) 0x03, a3));
            state[3][col] = (byte) (gmul((byte) 0x03, a0) ^ a1 ^ a2 ^ gmul((byte) 0x02, a3));
        }
    }

    public static void invMixColumns(byte[][] state) {
        for (int col = 0; col < 4; col++) {
            byte a0 = state[0][col];
            byte a1 = state[1][col];
            byte a2 = state[2][col];
            byte a3 = state[3][col];

            state[0][col] = (byte) (gmul((byte) 0x0e, a0) ^ gmul((byte) 0x0b, a1) ^ gmul((byte) 0x0d, a2) ^ gmul((byte) 0x09, a3));
            state[1][col] = (byte) (gmul((byte) 0x09, a0) ^ gmul((byte) 0x0e, a1) ^ gmul((byte) 0x0b, a2) ^ gmul((byte) 0x0d, a3));
            state[2][col] = (byte) (gmul((byte) 0x0d, a0) ^ gmul((byte) 0x09, a1) ^ gmul((byte) 0x0e, a2) ^ gmul((byte) 0x0b, a3));
            state[3][col] = (byte) (gmul((byte) 0x0b, a0) ^ gmul((byte) 0x0d, a1) ^ gmul((byte) 0x09, a2) ^ gmul((byte) 0x0e, a3));
        }
    }

    public static void addRoundKey(byte[][] state, byte[][] roundKey) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                state[row][col] ^= roundKey[row][col];
            }
        }
    }

    private static byte[] subWord(byte[] word) {
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (byte) (sbox[word[i] & 0xFF]);
        }
        return result;
    }

    private static byte[] rotWord(byte[] word) {
        byte[] result = new byte[4];
        result[0] = word[1];
        result[1] = word[2];
        result[2] = word[3];
        result[3] = word[0];
        return result;
    }

    public static byte[][][] keyExpansion(byte[] key) {
        byte[][][] roundKeys = new byte[Nr + 1][4][4];
        byte[] temp = new byte[4];
        
        // First round key is the original key
        for (int i = 0; i < Nk; i++) {
            roundKeys[0][0][i] = key[4*i];
            roundKeys[0][1][i] = key[4*i+1];
            roundKeys[0][2][i] = key[4*i+2];
            roundKeys[0][3][i] = key[4*i+3];
        }

        for (int i = 1; i <= Nr; i++) {
            // Calculate first word of round key
            temp[0] = roundKeys[i-1][0][3];
            temp[1] = roundKeys[i-1][1][3];
            temp[2] = roundKeys[i-1][2][3];
            temp[3] = roundKeys[i-1][3][3];
            
            temp = rotWord(temp);
            temp = subWord(temp);
            temp[0] ^= (byte) Rcon[i];
            
            roundKeys[i][0][0] = (byte) (roundKeys[i-1][0][0] ^ temp[0]);
            roundKeys[i][1][0] = (byte) (roundKeys[i-1][1][0] ^ temp[1]);
            roundKeys[i][2][0] = (byte) (roundKeys[i-1][2][0] ^ temp[2]);
            roundKeys[i][3][0] = (byte) (roundKeys[i-1][3][0] ^ temp[3]);
            
            // Calculate remaining words
            for (int j = 1; j < 4; j++) {
                roundKeys[i][0][j] = (byte) (roundKeys[i][0][j-1] ^ roundKeys[i-1][0][j]);
                roundKeys[i][1][j] = (byte) (roundKeys[i][1][j-1] ^ roundKeys[i-1][1][j]);
                roundKeys[i][2][j] = (byte) (roundKeys[i][2][j-1] ^ roundKeys[i-1][2][j]);
                roundKeys[i][3][j] = (byte) (roundKeys[i][3][j-1] ^ roundKeys[i-1][3][j]);
            }
        }
        
        return roundKeys;
    }

    public static byte[] encrypt(byte[] input, byte[] key) {
        byte[][][] roundKeys = keyExpansion(key);
        byte[][] state = toState(input);

        addRoundKey(state, roundKeys[0]);

        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        // Final round (no MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[Nr]);

        return fromState(state);
    }

    public static byte[] decrypt(byte[] input, byte[] key) {
        byte[][][] roundKeys = keyExpansion(key);
        byte[][] state = toState(input);

        addRoundKey(state, roundKeys[Nr]);
        invShiftRows(state);
        invSubBytes(state);

        for (int round = Nr-1; round >= 1; round--) {
            addRoundKey(state, roundKeys[round]);
            invMixColumns(state);
            invShiftRows(state);
            invSubBytes(state);
        }

        addRoundKey(state, roundKeys[0]);

        return fromState(state);
    }
}