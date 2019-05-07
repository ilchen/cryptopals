package com.cryptopals;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Created by Andrei Ilchenko on 04-05-19.
 */
public class Set7 extends Set2 {
    public static final SecretKeySpec  BLACK_SUBMARINE_SK = new SecretKeySpec("BLACK_ SUBMARINE".getBytes(), "AES");
    static final String   CHALLENGE49_SCT_TARGET = "http://localhost:8080/challenge49/sct?",
                          CHALLENGE49_MCT_TARGET = "http://localhost:8080/challenge49/mct?",
                          CHALLENGE50_TEXT = "alert('MZA who was that?');\n",
                          CHALLENGE50_TARGET_TEXT = "print('Ayo, the Wu is back!');//";
    static final Map<SecretKey, String>   KEYS_TO_ACCOUNTS;
    static {
        Map<SecretKey, String>   tmp = new HashMap<>();
        tmp.put(Set1.YELLOW_SUBMARINE_SK, "id100000012");
        tmp.put(BLACK_SUBMARINE_SK, "id100000013");
        KEYS_TO_ACCOUNTS = Collections.unmodifiableMap(tmp);
    }

    private final SecretKey   sk;
    private final int      base64BlockLen;
    final byte[]   zeroedIV;

    public Set7(int mode, SecretKey key) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        super(mode, key);
        sk = key;
        int   bs = cipher.getBlockSize();
        base64BlockLen = bs * 4 / 3 + (bs * 4 % 3 == 0  ?  0 : 4 - bs * 4 % 3);
        zeroedIV = new byte[cipher.getBlockSize()];
    }

    int getBase64BlockLen() {
        return base64BlockLen;
    }

    byte[] generateCbcMac(byte msg[], byte iv[]) {
        byte[]  cbcMAC = cipherCBC(msg, iv);
        return  Arrays.copyOfRange(cbcMAC, cbcMAC.length - cipher.getBlockSize(), cbcMAC.length);
    }

    String  generateCreditTransferMsg(String toBAN, BigDecimal amnt) {
        StringBuilder   sb = new StringBuilder("from=").append(KEYS_TO_ACCOUNTS.get(sk)).append("&to=").append(toBAN)
                .append("&amount=").append(amnt);
        byte[]   randomIV = new byte[cipher.getBlockSize()],  cbcMAC;
        secRandGen.nextBytes(randomIV);
        cbcMAC = generateCbcMac(sb.toString().getBytes(), randomIV);
        sb.append(DatatypeConverter.printBase64Binary(randomIV)).append(DatatypeConverter.printBase64Binary(cbcMAC));
        return  sb.toString();
    }

    String  generateMultipleCreditTransferMsg(String toBANs[], BigDecimal amounts[]) {
        if (toBANs.length < 1  ||  toBANs.length != amounts.length) {
            throw  new IllegalArgumentException(toBANs.length + " != " + amounts.length);
        }
        StringBuilder   sb = new StringBuilder("from=").append(KEYS_TO_ACCOUNTS.get(sk)).append("&tx_list=");
        sb.append(toBANs[0]).append(':').append(amounts[0]);
        for (int i=1; i < toBANs.length; i++) {
            sb.append(';').append(toBANs[i]).append(':').append(amounts[i]);
        }

        byte[]   cbcMAC;
        cbcMAC = generateCbcMac(sb.toString().getBytes(), zeroedIV);
        sb.append(DatatypeConverter.printBase64Binary(cbcMAC));
        return  sb.toString();
    }

    public String  validateCreditTransferMsg(String msg) {
        byte[]  iv = DatatypeConverter.parseBase64Binary(
                    msg.substring(msg.length() - (base64BlockLen << 1), msg.length() - base64BlockLen)),
                cbcMAC = DatatypeConverter.parseBase64Binary(msg.substring(msg.length() - base64BlockLen));
        if (Arrays.equals(cbcMAC, generateCbcMac(msg.substring(0, msg.length() - (base64BlockLen << 1)).getBytes(), iv)) ) {
            return  msg.substring(0, msg.length() - (base64BlockLen << 1));
        } else {
            return "";
        }
    }

    public String  validateMultipleCreditTransferMsg(String msg) {
        byte[]  cbcMAC = DatatypeConverter.parseBase64Binary(msg.substring(msg.length() - base64BlockLen, msg.length())),
                computedMAC = generateCbcMac(msg.substring(0, msg.length() - base64BlockLen).getBytes(StandardCharsets.ISO_8859_1), zeroedIV);
        if (Arrays.equals(cbcMAC, computedMAC) ) {
            return  msg.substring(0, msg.length() - base64BlockLen);
        } else {
            return "";
        }
    }

    static String  breakChallenge49(String legitMACedMessage, String forgedFrom, int base64Len) {
        byte[]   legitMsg = legitMACedMessage.getBytes(),  forgedMsg = forgedFrom.getBytes(),  diff = forgedMsg.clone();
        Set2.xorBlock(diff, legitMsg);
        byte[]  iv = DatatypeConverter.parseBase64Binary(
                legitMACedMessage.substring(legitMACedMessage.length() - (base64Len << 1),
                                            legitMACedMessage.length() - base64Len));
        String  cbcMAC = legitMACedMessage.substring(legitMACedMessage.length() - base64Len),
                qs = legitMACedMessage.substring(forgedFrom.length(), legitMACedMessage.length() - (base64Len << 1));
        diff = Arrays.copyOf(diff, iv.length);
        Set2.xorBlock(iv, diff);
        return  forgedFrom + qs + DatatypeConverter.printBase64Binary(iv) + cbcMAC;
    }

    static String  breakChallenge49Mct(String legitMACedMessage, String attackersMACedMessage,
                                       int blockSize, int base64Len) {
        byte[]   legitPaddedMsg = Set2.pkcs7Pad(
                        legitMACedMessage.substring(0, legitMACedMessage.length() - base64Len).getBytes(), blockSize),
                 legitCbcMac = DatatypeConverter.parseBase64Binary(
                         legitMACedMessage.substring(legitMACedMessage.length() - base64Len) ),
                 attackersFirstBlock = attackersMACedMessage.substring(0, 16).getBytes();
        String   attackersRemainingBlocks = attackersMACedMessage.substring(16, attackersMACedMessage.length());
        Set2.xorBlock(legitCbcMac, attackersFirstBlock);
        assert  Arrays.equals(legitPaddedMsg, new String(legitPaddedMsg, StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.ISO_8859_1));
        assert  Arrays.equals(legitCbcMac, new String(legitCbcMac, StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.ISO_8859_1));
        return  new String(legitPaddedMsg, StandardCharsets.ISO_8859_1)
                    + new String(legitCbcMac, StandardCharsets.ISO_8859_1) + attackersRemainingBlocks;
    }


    // URL Encoding is needed for the second part of Challenge 49 as when we xor the legit CBC-MAC of the victim message
    // with the first block of the attackers message, we end up with character that are not allowed in a query string.
    int  submitMACedMessageURLEncoded(String trgt, String MACedMessage) {
        String   parts[] = MACedMessage.split("&\\w+?=");
        parts = Arrays.copyOfRange(parts, 1, parts.length);
        String  sanitizedMsg = Arrays.stream(parts).reduce(MACedMessage, (accu, x) -> {
            String  res = "";
            try {
                res = URLEncoder.encode(x, StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException ignored) {
            }
            return  accu.replace(x, res);
        });
        return  submitMACedMessage(trgt, sanitizedMsg);
    }

    int  submitMACedMessage(String trgt, String MACedMessage) {
        try {
            HttpURLConnection httpCon = (HttpURLConnection)
                    new URL(trgt + MACedMessage).openConnection();
            httpCon.setRequestMethod( "POST" );
            httpCon.setRequestProperty("userid", KEYS_TO_ACCOUNTS.get(sk));
            return  httpCon.getResponseCode();
        } catch (IOException e) {
            return  0;
        }
    }

    static String  breakChallenge50(byte msg[], byte cbcMac[], byte trgtMsg[], int blockSize) {
        byte[]   trgtMsgPadded = Set2.pkcs7Pad(trgtMsg, blockSize),
                 msgFirstBlock = Arrays.copyOf(msg, blockSize),
                 msgRemainingBlocks = Arrays.copyOfRange(msg, blockSize, msg.length);
        Set2.xorBlock(cbcMac, msgFirstBlock);
        assert Arrays.equals(trgtMsgPadded, new String(trgtMsgPadded).getBytes());
        assert Arrays.equals(cbcMac, new String(cbcMac, StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.ISO_8859_1));
        return  new String(trgtMsgPadded)
                + new String(cbcMac, StandardCharsets.ISO_8859_1) + new String(msgRemainingBlocks);
    }

    public static void main(String[] args) {

        try {
            System.out.println("Challenge 49");

            Set7   encryptor = new Set7(Cipher.ENCRYPT_MODE, Set1.YELLOW_SUBMARINE_SK);
            String   macedMsg = encryptor.generateCreditTransferMsg("DE92500105173721848769", BigDecimal.valueOf(100)),
                     unmacedMsg = encryptor.validateCreditTransferMsg(macedMsg);
            System.out.printf("Maced message: %s%nUnmaced message: %s%n", macedMsg, unmacedMsg);
            assert  unmacedMsg.length() == macedMsg.length() - (encryptor.base64BlockLen << 1);

            assert  encryptor.submitMACedMessage(CHALLENGE49_SCT_TARGET, macedMsg) == 202;
            assert  encryptor.submitMACedMessage(CHALLENGE49_SCT_TARGET,
                        breakChallenge49(macedMsg, "from=id100000013", encryptor.base64BlockLen)) == 202;

            macedMsg = encryptor.generateMultipleCreditTransferMsg(
                    new String[] { "NL35ABNA7925653426", "PT61003506835911954593562"},
                    new BigDecimal[] {   BigDecimal.valueOf(101),  BigDecimal.valueOf(102)});
            assert  !encryptor.validateMultipleCreditTransferMsg(macedMsg).equals("");
            assert  encryptor.submitMACedMessageURLEncoded(CHALLENGE49_MCT_TARGET, macedMsg) == 202;

            String   attackersMacedMsg = encryptor.generateMultipleCreditTransferMsg(
                        new String[] { "RO63EEOM5869471527249753"},
                        new BigDecimal[] {   BigDecimal.valueOf(10043041)   }),
                    forgedMacedMsg = breakChallenge49Mct(macedMsg, attackersMacedMsg,
                            encryptor.cipher.getBlockSize(), encryptor.base64BlockLen);
            assert  !encryptor.validateMultipleCreditTransferMsg(forgedMacedMsg).equals("");
            assert  encryptor.submitMACedMessageURLEncoded(CHALLENGE49_MCT_TARGET, forgedMacedMsg) == 202;

            System.out.println("Challenge 50");
            byte[]  trgtMac = encryptor.generateCbcMac(CHALLENGE50_TEXT.getBytes(), encryptor.zeroedIV),
                    mac = encryptor.generateCbcMac(CHALLENGE50_TARGET_TEXT.getBytes(), encryptor.zeroedIV);
            System.out.printf("The CBC-MAC of %s%nis: %s%n",
                    CHALLENGE50_TEXT, DatatypeConverter.printHexBinary(trgtMac).toLowerCase());
            attackersMacedMsg = breakChallenge50(CHALLENGE50_TEXT.getBytes(), mac,
                    CHALLENGE50_TARGET_TEXT.getBytes(), encryptor.cipher.getBlockSize());
            mac = encryptor.generateCbcMac(attackersMacedMsg.getBytes(StandardCharsets.ISO_8859_1), encryptor.zeroedIV);
            System.out.printf("The CBC-MAC of %s%nis: %s%n",
                    attackersMacedMsg, DatatypeConverter.printHexBinary(mac).toLowerCase());
            assert  Arrays.equals(trgtMac, mac);

            ScriptEngineManager   manager = new ScriptEngineManager();
            ScriptEngine   engine = manager.getEngineByName("JavaScript");
            engine.eval(attackersMacedMsg);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
