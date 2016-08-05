package net.lardcave.keepassnfcapplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

// TODO: encrypt-then-MAC: http://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac

public class KeepassNFC extends Applet {
	final static byte CLA_CARD_KPNFC_CMD           = (byte)0xB0;

	final static byte INS_CARD_GET_CARD_PUBKEY     = (byte)0x70;
	final static byte INS_CARD_SET_PASSWORD_KEY    = (byte)0x71;
	final static byte INS_CARD_PREPARE_DECRYPTION  = (byte)0x72;
	final static byte INS_CARD_DECRYPT_BLOCK       = (byte)0x73;
	final static byte INS_CARD_GET_VERSION         = (byte)0x74;
	final static byte INS_CARD_GENERATE_CARD_KEY   = (byte)0x75;
	final static byte INS_CARD_WRITE_TO_SCRATCH    = (byte)0x76;

	final static byte RESPONSE_SUCCEEDED           = (byte)0x1;
	final static byte RESPONSE_FAILED              = (byte)0x2;

	final static byte VERSION                      = (byte)0x1;

	final static byte RSA_ALGORITHM                = KeyPair.ALG_RSA_CRT;
	final static short RSA_KEYLENGTH               = KeyBuilder.LENGTH_RSA_2048;

	private KeyPair card_key;
	private AESKey password_key;
	private AESKey transaction_key;

	private Cipher card_cipher;
	private Cipher transaction_cipher;
	private Cipher password_cipher;

	private byte[] scratch_area;
	private byte[] aes_key_temporary;
	private boolean card_cipher_initialised;

	protected KeepassNFC(byte[] bArray, short bOffset, byte bLength)
	{
		card_key = new KeyPair(RSA_ALGORITHM, RSA_KEYLENGTH);
		password_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		transaction_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

		card_cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		password_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		transaction_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

		scratch_area = JCSystem.makeTransientByteArray((short)260, JCSystem.CLEAR_ON_DESELECT);
		aes_key_temporary = JCSystem.makeTransientByteArray((short)260, JCSystem.CLEAR_ON_DESELECT);
		card_cipher_initialised = false;

		/*
		if(bLength == 32) {
			// Initial keys.
			card_key.setKey(bArray, bOffset);
			password_key.setKey(bArray, (short)(bOffset + 16));
		}

		card_cipher.init(card_key, Cipher.MODE_DECRYPT);
		password_cipher.init(password_key, Cipher.MODE_DECRYPT);
		*/

		register();
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
	{
		new KeepassNFC(bArray, bOffset, bLength);
	}

	public boolean select()
	{
		return true;
	}

	public void deselect()
	{
	}

	public void process(APDU apdu) throws ISOException
	{
		byte[] buffer = apdu.getBuffer();

		if(selectingApplet())
			return;

		if(buffer[ISO7816.OFFSET_CLA] == CLA_CARD_KPNFC_CMD) {
			switch(buffer[ISO7816.OFFSET_INS]) {
				case INS_CARD_GET_CARD_PUBKEY:
					getCardPubKey(apdu);
					break;
				case INS_CARD_SET_PASSWORD_KEY:
					setPasswordKey(apdu);
					break;
				case INS_CARD_PREPARE_DECRYPTION:
					prepareDecryption(apdu);
					break;
				case INS_CARD_DECRYPT_BLOCK:
					decryptBlock(apdu);
					break;
				case INS_CARD_GET_VERSION:
					getVersion(apdu);
					break;
				case INS_CARD_GENERATE_CARD_KEY:
					generateCardKey(apdu);
					break;
				case INS_CARD_WRITE_TO_SCRATCH:
					writeToScratch(apdu);
					break;
						
			}
		}
	}

	private static final short MAX_PUBKEY_SEND_LENGTH = 120;

	protected void getCardPubKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		/* in:
		 * 1 byte: type of request:
		 *     1: get exponent
		 *     2: get modulus (start)
		 *     3: get modulus (continue)
		 * 2 bytes: start byte (if requesting modulus-continue) or 00 00 (otherwise)
		 * out (for exponent):
		 *    1 byte: RESPONSE_SUCCEEDED
		 *    2 bytes: length of exponent
		 *    n bytes: exponent (up to 4 bytes)
		 * out (for modulus):
		 *    1 byte: REPONSE_SUCCEEDED
		 *    2 bytes: number of bytes sent this time
		 *    2 bytes: bytes remaining to send
		 *    n bytes: modulus (up to MAX_PUBKEY_SEND_LENGTH bytes)
		 *
		 *
		 * Client must first retrieve exponent, then
		 * modulus.
		 * Scratch buffer management:
		 * 2 bytes: total length of buffer (in bytes)
		 * n bytes: exponent or modulus.
		*/

		short lengthOut = 0;
		byte command = buffer[ISO7816.OFFSET_CDATA];
		if(command == 1) {
			// get exponent
			RSAPublicKey key = (RSAPublicKey) card_key.getPublic();
			short exponentLength = key.getExponent(buffer, (short)(ISO7816.OFFSET_CDATA + 3));
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
			Util.setShort(buffer, (short)(ISO7816.OFFSET_CDATA + 1), exponentLength);

			lengthOut = (short)(exponentLength + 3);
		} else if (command == 2 || command == 3) {
			if(command == 2) {
				// get modulus, start
				RSAPublicKey key = (RSAPublicKey) card_key.getPublic();
				short modulusLength = key.getModulus(scratch_area, (short)2);
				Util.setShort(scratch_area, (short)0, modulusLength);
				// fall through
			}
			short modulusLength = Util.getShort(scratch_area, (short)0);
			short offset = Util.getShort(buffer, (short)(ISO7816.OFFSET_CDATA + 1));
			short amountToSend = (short)(modulusLength - offset);
			if(amountToSend > MAX_PUBKEY_SEND_LENGTH)
				amountToSend = MAX_PUBKEY_SEND_LENGTH;
			if(amountToSend < 0)
				amountToSend = 0;

			Util.arrayCopy(scratch_area, (short)(2 + offset), buffer, (short)(ISO7816.OFFSET_CDATA + 5), amountToSend);

			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
			Util.setShort(buffer, (short)(ISO7816.OFFSET_CDATA + 1), amountToSend);
			Util.setShort(buffer, (short)(ISO7816.OFFSET_CDATA + 3), (short)(modulusLength - offset - amountToSend));

			lengthOut = (short)(amountToSend + 5);
		} else {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_FAILED;
		}

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, lengthOut);
	}

	protected void setPasswordKey(APDU apdu)
	{
		/* Password key is encrypted with the card key and we expect it to be stored in the scratch area. */
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		decryptWithCardKey(scratch_area, (short)0, aes_key_temporary);
		password_key.setKey(aes_key_temporary, (short)0);
		buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
	}


	protected void prepareDecryption(APDU apdu)
	{
		/* We expect:
		 * scratch area contains: transaction key (encrypted with card key)
		 * 16 bytes: IV for transaction key (plaintext)
		 * 16 bytes: IV for password key (plaintext)
		*/
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		if(length == 32) {
			decryptWithCardKey(scratch_area, (short)0, aes_key_temporary);
			transaction_key.setKey(aes_key_temporary, (short)0);

			transaction_cipher.init(transaction_key, Cipher.MODE_ENCRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 0), (short)16);
			password_cipher.init(password_key, Cipher.MODE_DECRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 16), (short)16);

			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		} else {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_FAILED;
		}

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
	}

	protected void decryptBlock(APDU apdu)
	{
		/* Decrypt the block with the password key, then encrypt it with the transaction key. */
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		boolean succeeded = false;

		short decrypted = password_cipher.update(buffer, (short)ISO7816.OFFSET_CDATA, (short)16, scratch_area, (short)0);
		if(decrypted == 16) {
			/* We decrypted the block successfully, now re-encrypt it with the transaction key. */
			short encrypted = transaction_cipher.update(scratch_area, (short)0, (short)16, buffer, (short)(ISO7816.OFFSET_CDATA + 1));
			if(encrypted == 16) {
				/* We encrypted the new block successfully. */
				succeeded = true;
			}
		}

		buffer[ISO7816.OFFSET_CDATA] = succeeded ? RESPONSE_SUCCEEDED : RESPONSE_FAILED;
		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)17);
	}

	protected void getVersion(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		buffer[ISO7816.OFFSET_CDATA + 1] = VERSION;

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)2);
	}

	protected void generateCardKey(APDU apdu)
	{
		/* in: nothing
		 * out: two bytes indicating the length of the key
		 */
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		card_cipher_initialised = false;
		card_key.genKeyPair();

		buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		buffer[ISO7816.OFFSET_CDATA + 1] = (RSA_KEYLENGTH >> 8) & 0xFF;
		buffer[ISO7816.OFFSET_CDATA + 2] = (RSA_KEYLENGTH & 0xFF);

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)3);
	}

	protected void writeToScratch(APDU apdu)
	{
		/* in: 2 bytes: offset in scratch
		 *     n bytes: data
		 * out: success | fail
		 */
		byte[] buffer = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();

		short offset = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
		Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + 2), scratch_area, offset, (short)(length - 2));

		buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
	}

	private boolean decryptWithCardKey(byte[] input, short offset, byte[] output)
	{
		if(!card_cipher_initialised) {
			RSAPrivateCrtKey private_key = (RSAPrivateCrtKey)card_key.getPrivate();
			card_cipher.init(private_key, Cipher.MODE_DECRYPT);

			card_cipher_initialised = true;
		}

		card_cipher.doFinal(input, offset, (short)(RSA_KEYLENGTH / 8), output, (short)0);
		return true;
	}

	/*
	protected void cmdEcho(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short  len = apdu.setIncomingAndReceive();

		buffer[ISO7816.OFFSET_CDATA] ++;

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)16);
	}
	*/

}
