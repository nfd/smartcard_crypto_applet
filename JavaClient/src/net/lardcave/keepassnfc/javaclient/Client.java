package net.lardcave.keepassnfc.javaclient;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Client {
    @Parameter(names="-card-key", description="Use card key (hex, 16 bytes / 32 hex chars)")
    public String cardKeyString;

    @Parameter(names="-password-key", description="Password key (hex)")
    public String passwordKeyString;

    @Parameter(names="-default-keys", description="Use test values for password and card keys")
    public boolean useDefaultKeys;

    @Parameter(names="-data", description="Data (hex string)")
    public String testDataString;

    @Parameter(description="Command {set_card_key, set_password_key, encrypt, decrypt}")
    public List<String> command = new ArrayList<>();

    private static final byte[] TEST_CARD_KEY = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    private static final byte[] TEST_PASSWORD_KEY = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    private static final byte[] TEST_INPUT = {(byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x73, (byte) 0x69,
            (byte) 0x6d, (byte) 0x6d, (byte) 0x6f, (byte) 0x6e, (byte) 0x73, (byte) 0x20, (byte) 0x2d, (byte) 0x20,
            (byte) 0x79, (byte) 0x75, (byte) 0x6d};

    private byte[] cardKey;
    private byte[] passwordKey;
    private byte[] passwordKeyIv;
    private byte[] testData;
    private SecureRandom random;

    private final static byte CLA_CARD_KPNFC_CMD           = (byte)0xB0;

    private final static byte INS_CARD_SET_CARD_KEY        = (byte)0x70;
    private final static byte INS_CARD_SET_PASSWORD_KEY    = (byte)0x71;
    private final static byte INS_CARD_PREPARE_DECRYPTION  = (byte)0x72;
    private final static byte INS_CARD_DECRYPT_BLOCK       = (byte)0x73;
    private final static byte INS_CARD_GET_VERSION         = (byte)0x74;

    private final static byte RESPONSE_SUCCEEDED           = (byte)0x1;
    private final static byte RESPONSE_FAILED              = (byte)0x2;

    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;

    // AID of the KPNFC decryptor: f0 37 54 72  80 4f d5 fa  0f 24 3e 42  c1 b6 38 25
    public static final byte[] selectAppletAPDU = {
            (byte) 0x00, // cla
            (byte) 0xA4, // ins
            (byte) 0x04, // P1
            (byte) 0x00, // P2
            (byte) 0x10, // Length of AID,
            (byte) 0xf0, (byte) 0x37, (byte) 0x54, (byte) 0x72, (byte) 0x80, (byte) 0x4f, (byte) 0xd5, (byte) 0xfa, // AID
            (byte) 0x0f, (byte) 0x24, (byte) 0x3e, (byte) 0x42, (byte) 0xc1, (byte) 0xb6, (byte) 0x38, (byte) 0x25, // AID
            (byte) 0x00, // apparently optional
    };

    public static void main(String[] args) throws CardException {

        Client client = new Client();
        new JCommander(client, args);

        client.run();
    }

    public void run() throws CardException {
        if(command.size() != 1) {
            System.err.println("Specify a command.");
            return;
        }

        random = new SecureRandom();

        cardKey = new byte[16];
        passwordKey = new byte[16];

        if(useDefaultKeys) {
            System.arraycopy(TEST_CARD_KEY, 0, cardKey, 0, cardKey.length);
            System.arraycopy(TEST_PASSWORD_KEY, 0, passwordKey, 0, passwordKey.length);
        } else {
            if(cardKeyString != null) {
                cardKey = decodeHexString(cardKeyString);
            } else {
                cardKey = randomBytes(16);
                //System.out.println("Chose random card key: " + toHex(cardKey));
            }

            if(passwordKeyString != null) {
                passwordKey = decodeHexString(passwordKeyString);
            } else {
                passwordKey = randomBytes(16);
                //System.out.println("Chose random password key: " + toHex(passwordKey));
            }
        }

        passwordKeyIv = new byte[16];

        if(testDataString != null)
            testData = decodeHexString(testDataString);

        //System.out.println("You specified data: " + toHex(testData));

        switch (command.get(0)) {
            case "set_card_key":
                setCardKey();
                break;
            case "set_password_key":
                setPasswordKey();
                break;
            case "encrypt":
                encrypt();
                break;
            case "decrypt":
                decrypt();
                break;
            case "version":
                version();
                break;
            default:
                System.err.println("Unknown command '" + command + "'");
                break;
        }
    }

    public void setCardKey() throws CardException {
        byte[] command = constructApdu(INS_CARD_SET_CARD_KEY, cardKey);

        sendSingleCommand(command);
        System.out.println("Card key set to " + toHex(cardKey));
    }

    public void setPasswordKey() throws CardException {
        byte[] encryptedPasswordKey = encryptWithCardKey(passwordKey);

        if(encryptedPasswordKey != null) {
            byte[] command = constructApdu(INS_CARD_SET_PASSWORD_KEY, encryptedPasswordKey);

            sendSingleCommand(command);
            System.out.println("Password key set to " + toHex(passwordKey));
        }
    }

    private byte[] sendSingleCommand(byte[] command) throws CardException {
        CardChannel channel = getCardChannel();
        if(channel != null) {
            ResponseAPDU response = sendAPDU(channel, command);
            return response.getBytes();
        } else {
            return null;
        }
    }

    private byte[] encryptWithCardKey(byte[] input) {
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/ECB/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        SecretKeySpec key = new SecretKeySpec(cardKey, "AES");
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        try {
            return cipher.doFinal(input);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void encrypt() {
        /* Doesn't use the card -- simply encrypts test data with the password key for testing. */
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return;
        }

        SecretKeySpec key = new SecretKeySpec(passwordKey, "AES");
        IvParameterSpec iv = new IvParameterSpec(passwordKeyIv);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return;
        }

        byte[] result;
        try {
            result = cipher.doFinal(TEST_INPUT);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return;
        }

        System.out.println("Original:  " + toHex(TEST_INPUT));
        System.out.println("IV:        " + toHex(passwordKeyIv));
        System.out.println("Encrypted: " + toHex(result));
    }

    public byte[] randomBytes(int count) {
        byte[] theBytes = new byte[count];
        random.nextBytes(theBytes);
        return theBytes;
    }

    public void decrypt() throws CardException {
        // Generate a random transaction key and IV.
        byte[] transactionKey = randomBytes(16);
        byte[] transactionIv = randomBytes(16);

        byte[] encryptedTransactionKey = encryptWithCardKey(transactionKey);
        if(encryptedTransactionKey == null) {
            return;
        }

        // Connect to the card and establish a transaction key.
        byte[] apdu;
        byte[] transactionParameters = new byte[48];

        // Prepare decryption: 16 bytes of transaction key, encrypted with the card key,
        // followed by two IVs.
        System.arraycopy(encryptedTransactionKey, 0, transactionParameters, 0, 16);
        System.arraycopy(transactionIv, 0, transactionParameters, 16, 16);
        System.arraycopy(passwordKeyIv, 0, transactionParameters, 32, 16);

        apdu = constructApdu(INS_CARD_PREPARE_DECRYPTION, transactionParameters);
        CardChannel channel = getCardChannel();

        if(channel != null) {
            ResponseAPDU response = sendAPDU(channel, apdu);
            System.out.println(toHex(response.getBytes()));

            // Decryption has been prepared, so decrypt the text.
            apdu = constructApdu(INS_CARD_DECRYPT_BLOCK, testData);
            response = sendAPDU(channel, apdu);
            System.out.println(toHex(response.getBytes()));

            // This is encrypted with the transaction key, so decrypt it.
            byte[] decrypted = decryptWithTransactionKey(response.getBytes(), 1, 16, transactionKey, transactionIv);
            if(decrypted != null) {
                System.out.println(toHex(decrypted));
            }
        }
    }

    public void version() throws CardException {
        byte[] nullPayload = {};
        byte[] command = constructApdu(INS_CARD_GET_VERSION, nullPayload);

        byte[] response = sendSingleCommand(command);

        if(response != null) {
            System.out.println("Applet version " + response[1]);
        }
    }

    public byte[] decryptWithTransactionKey(byte[] source, int start, int length, byte[] keyBytes, byte[] ivBytes)
    {
        Cipher cipher;

        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }

        byte[] result;
        try {
            result = cipher.doFinal(source, start, length);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }

        return result;
    }


    public static byte[] constructApdu(byte command, byte[] data)
    {
        byte[] apdu = new byte[HEADER_LENGTH + data.length];
        apdu[OFFSET_CLA] = CLA_CARD_KPNFC_CMD;
        apdu[OFFSET_INS] = command;
        apdu[OFFSET_P1] = (byte)0;
        apdu[OFFSET_P2] = (byte)0;
        apdu[OFFSET_LC] = (byte)data.length;

        System.arraycopy(data, 0, apdu, OFFSET_DATA, data.length);

        return apdu;
    }

    public CardChannel getCardChannel() throws CardException {

        CardTerminal terminal = getFirstCardTerminal();

        if(terminal == null)
            return null;

        if(!terminal.isCardPresent()) {
            System.err.println("No card present in first terminal");
            return null;
        }

        Card card = terminal.connect("*");
        CardChannel channel = card.getBasicChannel();

        // reset card (?!)
        ATR atr = card.getATR();

        // Select applet
        ResponseAPDU response = sendAPDU(channel, selectAppletAPDU);
        byte[] responseBytes = response.getBytes();

        if(responseBytes[0] != (byte)0x90 && responseBytes[1] != (byte)0x00) {
            System.out.println("Applet select failed: " + toHex(responseBytes));
            // see https://www.eftlab.com.au/index.php/site-map/knowledge-base/118-apdu-response-list

            return null;
        }

        return channel;
    }

    private static CardTerminal getFirstCardTerminal() throws CardException {
        TerminalFactory terminalFactory = TerminalFactory.getDefault();

        List<CardTerminal> readers = terminalFactory.terminals().list();
        if(readers.size() == 0) {
            System.err.println("No card terminals found.");
            return null;
        } else {
            return readers.get(0);
        }
    }

    private static ResponseAPDU sendAPDU(CardChannel channel, byte[] apdu) throws CardException {
        System.out.println("OUT: " + toHex(apdu));
        CommandAPDU command = new CommandAPDU(apdu);

        ResponseAPDU response = channel.transmit(command);
        System.out.println("IN:  " + toHex(response.getBytes()));
        return response;
    }

    public static String toHex(byte[] data) {
        StringBuilder buf = new StringBuilder();

        for(byte b: data) {
            buf.append(nibbleToChar((byte)((b & 0xff) >> 4))); // java is bs
            buf.append(nibbleToChar((byte)(b & 0xf)));
            buf.append(' ');
        }

        return buf.toString();
    }

    public static char nibbleToChar(byte nibble) {
        assert(nibble < 16);

        if(nibble < 10)
            return (char)('0' + nibble);
        else
            return (char)('A' + (nibble - 10));
    }

    public static byte charToNibble(char c)
    {
        if(c >= '0' && c <= '9')
            return (byte)(c - '0');
        if(c >= 'A' && c <= 'F')
            return (byte)(c - 'A' + 10);
        if(c >= 'a' && c <= 'f')
            return (byte)(c - 'a' + 10);

        throw new RuntimeException("Not a hex character");
    }

    public static byte[] decodeHexString(String s)
    {
        byte[] decoded = new byte[8]; // initial length

        byte currentByte = 0;
        boolean inNibble = false;
        int index = 0;

        for(char c: s.toCharArray()) {
            if(c == ' ' || c == ':')
                continue;

            currentByte |= charToNibble(c);
            if(inNibble) {
                if(index == decoded.length) {
                    // Out of space, so double it.
                    byte[] newDecoded = new byte[decoded.length * 2];
                    System.arraycopy(decoded, 0, newDecoded, 0, decoded.length);
                    decoded = newDecoded;
                }

                // write the completed byte.
                decoded[index] = currentByte;
                index++;
                inNibble = false;
                currentByte = 0;
            } else {
                currentByte <<= 4;
                inNibble = true;
            }
        }

        return Arrays.copyOfRange(decoded, 0, index);
    }

}
