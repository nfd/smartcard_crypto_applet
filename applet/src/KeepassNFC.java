package net.lardcave.keepassnfcapplet;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

// TODO: encrypt-then-MAC: http://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac

public class KeepassNFC extends Applet {
	final static byte CLA_CARD_KPNFC_CMD           = (byte)0xB0;

	final static byte INS_CARD_SET_CARD_KEY        = (byte)0x70;
	final static byte INS_CARD_SET_PASSWORD_KEY    = (byte)0x71;
	final static byte INS_CARD_PREPARE_DECRYPTION  = (byte)0x72;
	final static byte INS_CARD_DECRYPT_BLOCK       = (byte)0x73;
	final static byte INS_CARD_GET_VERSION         = (byte)0x74;

	final static byte RESPONSE_SUCCEEDED           = (byte)0x1;
	final static byte RESPONSE_FAILED              = (byte)0x2;

	final static byte VERSION                      = (byte)0x1;

	private AESKey card_key;
	private AESKey password_key;
	private AESKey transaction_key;

	private Cipher card_cipher;
	private Cipher transaction_cipher;
	private Cipher password_cipher;

	private byte[] scratch_area;

	protected KeepassNFC(byte[] bArray, short bOffset, byte bLength)
	{
		card_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		password_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		transaction_key = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

		card_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		password_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		transaction_cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

		scratch_area = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);

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
				case INS_CARD_SET_CARD_KEY:
					setCardKey(apdu);
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
			}
		}
	}

	protected void setCardKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		if(length == 16) {
			card_key.setKey(buffer, ISO7816.OFFSET_CDATA);
			card_cipher.init(card_key, Cipher.MODE_DECRYPT);

			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		} else {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_FAILED;
		} 

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
	}

	protected void setPasswordKey(APDU apdu)
	{
		/* Password key is encrypted with the card key. */
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		if(length == 16) {
			decryptWithCardKey(buffer, (short)ISO7816.OFFSET_CDATA, (short)16, scratch_area);
			password_key.setKey(scratch_area, (short)0);
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_SUCCEEDED;
		} else {
			buffer[ISO7816.OFFSET_CDATA] = RESPONSE_FAILED;
		} 

		apdu.setOutgoingAndSend((short)ISO7816.OFFSET_CDATA, (short)1);
	}


	protected void prepareDecryption(APDU apdu)
	{
		/* We expect:
		 * 16 bytes: transaction key (encrypted with card key)
		 * 16 bytes: IV for transaction key (plaintext)
		 * 16 bytes: IV for password key (plaintext)
		*/
		byte[] buffer = apdu.getBuffer();
		short length  = apdu.setIncomingAndReceive();

		if(length == 48) {
			decryptWithCardKey(buffer, (short)ISO7816.OFFSET_CDATA, (short)16, scratch_area);
			transaction_key.setKey(scratch_area, (short)0);

			transaction_cipher.init(transaction_key, Cipher.MODE_ENCRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 16), (short)16);
			password_cipher.init(password_key, Cipher.MODE_DECRYPT, buffer, (short)(ISO7816.OFFSET_CDATA + 32), (short)16);

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

	private boolean decryptWithCardKey(byte[] input, short offset, short length, byte[] output)
	{
		card_cipher.doFinal(input, offset, length, output, (short)0);
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
