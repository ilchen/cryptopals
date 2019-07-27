package com.cryptopals;

import com.cryptopals.set_7.DiamondStructure;
import com.cryptopals.set_7.MD4CollisionsFinder;
import com.cryptopals.set_7.MDHelper;
import com.cryptopals.set_7.RC4SingleByteBiasAttackHelper;
import lombok.SneakyThrows;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.xml.bind.DatatypeConverter;

import static javax.xml.bind.DatatypeConverter.parseBase64Binary;
import static javax.xml.bind.DatatypeConverter.printBase64Binary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.function.ToIntFunction;
import java.util.zip.Deflater;

/**
 * Created by Andrei Ilchenko on 04-05-19.
 */
public class Set7 extends Set3 {
    public static final SecretKeySpec  BLACK_SUBMARINE_SK = new SecretKeySpec("BLACK_ SUBMARINE".getBytes(), "AES");
    static final String   CHALLENGE49_SCT_TARGET = "http://localhost:8080/challenge49/sct?",
                          CHALLENGE49_MCT_TARGET = "http://localhost:8080/challenge49/mct?",
                          CHALLENGE50_TEXT = "alert('MZA who was that?');\n",
                          CHALLENGE50_TARGET_TEXT = "print('Ayo, the Wu is back!');//",
                          CHALLENGE56_COOKIE = new String(DatatypeConverter.parseBase64Binary("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F"));
    private static final String  CHALLENGE51_COOKIE_NAME = "sessionid=",
                                 CHALLENGE51_REQUEST_TEMPLATE =
                                  "POST / HTTP/1.1%n Host: hapless.com%n"
                                    + "Cookie: " + CHALLENGE51_COOKIE_NAME + "TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=%n"
                                    + "Content-Length: %d%n%s%n";

    private static final int    CHALLENGE51_COOKIE_LENGTH = 44;
    private static final char   BASE64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toCharArray();
    private static final String   BASE64_BIGRAMS[] = new String[BASE64_CHARS.length * BASE64_CHARS.length];
    static {
        int   i = 0;            /* To speed up calculations in Challenge 51 */
        for (char base64Char1 : BASE64_CHARS) {
            for (char base64Char2 : BASE64_CHARS) {
                BASE64_BIGRAMS[i++] = new String(new char[]{base64Char1, base64Char2});
            }
        }
    }

    private static final Map<SecretKey, String>   KEYS_TO_ACCOUNTS;
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
        sb.append(printBase64Binary(randomIV)).append(printBase64Binary(cbcMAC));
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
        sb.append(printBase64Binary(cbcMAC));
        return  sb.toString();
    }

    public String  validateCreditTransferMsg(String msg) {
        byte[]  iv = parseBase64Binary(
                    msg.substring(msg.length() - (base64BlockLen << 1), msg.length() - base64BlockLen)),
                cbcMAC = parseBase64Binary(msg.substring(msg.length() - base64BlockLen));
        if (Arrays.equals(cbcMAC, generateCbcMac(msg.substring(0, msg.length() - (base64BlockLen << 1)).getBytes(), iv)) ) {
            return  msg.substring(0, msg.length() - (base64BlockLen << 1));
        } else {
            return "";
        }
    }

    public String  validateMultipleCreditTransferMsg(String msg) {
        byte[]  cbcMAC = parseBase64Binary(msg.substring(msg.length() - base64BlockLen)),
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
        byte[]  iv = parseBase64Binary(
                legitMACedMessage.substring(legitMACedMessage.length() - (base64Len << 1),
                                            legitMACedMessage.length() - base64Len));
        String  cbcMAC = legitMACedMessage.substring(legitMACedMessage.length() - base64Len),
                qs = legitMACedMessage.substring(forgedFrom.length(), legitMACedMessage.length() - (base64Len << 1));
        diff = Arrays.copyOf(diff, iv.length);
        Set2.xorBlock(iv, diff);
        return  forgedFrom + qs + printBase64Binary(iv) + cbcMAC;
    }

    static String  breakChallenge49Mct(String legitMACedMessage, String attackersMACedMessage,
                                       int blockSize, int base64Len) {
        byte[]   legitPaddedMsg = Set2.pkcs7Pad(
                        legitMACedMessage.substring(0, legitMACedMessage.length() - base64Len).getBytes(), blockSize),
                 legitCbcMac = parseBase64Binary(legitMACedMessage.substring(legitMACedMessage.length() - base64Len) ),
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

    private static byte[]  challege51OracleHelper(String msg) {
        String   request = String.format(CHALLENGE51_REQUEST_TEMPLATE, msg.length(), msg);
        Deflater compresser = new Deflater();
        byte[]   requestBytes = new byte[request.length()];
        compresser.setInput(request.getBytes());
        compresser.finish();
        int   len = compresser.deflate(requestBytes);
        return  Arrays.copyOf(requestBytes, len);
    }

    int  challenge51OracleCTR(String msg) {
        return  cipherCTR(challege51OracleHelper(msg), secRandGen.nextLong()).length;
    }

    int  challenge51OracleCBC(String msg) {
        byte[]   iv = new byte[cipher.getBlockSize()];
        secRandGen.nextBytes(iv);
        return  cipherCBC(challege51OracleHelper(msg), iv).length;
    }

    private static StringBuilder  detectPadding(StringBuilder prefix, ToIntFunction<String> oracle) {
        char   nonBase64[] = "!@#$%^&*()-`~[]}{\"'_|".toCharArray();
        StringBuilder   sb = new StringBuilder();
        int   start = oracle.applyAsInt(sb.toString());
        int   i = 0;
        do {
            sb.append(nonBase64[i++]);
        } while (oracle.applyAsInt(prefix + sb.toString()) == start);
        sb.deleteCharAt(i - 1);
        return  sb;
    }

    private static int  detectBlocksize(ToIntFunction<String> oracle) {
        StringBuilder   sb = new StringBuilder();
        int   start = oracle.applyAsInt(sb.toString()),  len;
        for (char ch: "!@#$%^&*()-`~[]}{\"'_|".toCharArray()) {
            sb.append(ch);
            len = oracle.applyAsInt(sb.toString());
            if (len > start)  return  len - start;
        }
        return  0;
    }

    /**
     * Carries our the CRIME attack against both stream and block ciphers.
     * @see <a href="https://docs.google.com/presentation/d/11eBmGiHbYcHR9gL5nDyZChu_-lCa2GizeuOfaLU2HOU/edit#slide=id.g1d134dff_1_10"/>
     */
    static String  breakChallenge51(ToIntFunction<String> oracle) {
        List<StringBuilder>   candidates = new ArrayList<>();
        StringBuilder   sb_ = new StringBuilder(CHALLENGE51_COOKIE_NAME);
        candidates.add(sb_);
        int   bestLen = oracle.applyAsInt(sb_.toString()),  i = 0;
        StringBuilder   padding = detectPadding(sb_, oracle);
        boolean   isCBC = padding.length() > 0;
        int   blockSize = isCBC  ?  detectBlocksize(oracle) : 0;

        while (i < CHALLENGE51_COOKIE_LENGTH) {
            List<StringBuilder>  potentialCandidates = new ArrayList<>();

            for (int cand=0; cand < candidates.size(); cand++) {
                StringBuilder   sb = candidates.get(cand);
                if (isCBC)  {
                    padding = detectPadding(sb, oracle);
                }
                int   j = 0,  k,  idxPossibleMatch = -1;
                sb.append("01");

                do {
                    sb.replace(sb.length() - 2, sb.length(), BASE64_BIGRAMS[j]);
                    k = oracle.applyAsInt(sb.toString() + padding);
                    if (isCBC && k > bestLen  ||  !isCBC && k == bestLen + 1) {
                        if (isCBC  &&  oracle.applyAsInt(
                                sb.toString() + padding.substring(0, padding.length() - 1)) > bestLen)  continue;
                        if (idxPossibleMatch != -1) {
                            StringBuilder sb2 = new StringBuilder(sb);
                            sb2.replace(sb2.length() - 2, sb2.length(), BASE64_BIGRAMS[idxPossibleMatch]);
                            potentialCandidates.add(sb2);
                        }
                        idxPossibleMatch = j;
                    }
                } while (k > bestLen  &&  ++j < BASE64_BIGRAMS.length);

                if (j == BASE64_BIGRAMS.length) {
                    if (idxPossibleMatch == -1) {  /* dead end */
                        candidates.remove(cand--); /* ensure we iterate through this index again */
                        potentialCandidates.clear();
                        System.out.println("Discarding: " + sb);
//                        if (candidates.size() == 0) { /* we moved beyond the end of the cookie */
//                            sb.delete(sb.length() - 2, sb.length());
//                            System.out.println("Backtracking to: " + sb);
//                            return  sb.toString();
//                        }
                    } else {
//                                                    /* we moved beyond the end of the cookie */
//                        if (sb.charAt(sb.length() - 3) == '='  &&  !BASE64_BIGRAMS[idxPossibleMatch].equals("==")) {
//                            sb.delete(sb.length() - 2, sb.length());
//                            return  sb.toString();
//                        }
                        sb.replace(sb.length() - 2, sb.length(), BASE64_BIGRAMS[idxPossibleMatch]);
                        if (!isCBC) {
                            bestLen++;
                        } else if (padding.length() < 2) {
                            bestLen += blockSize;  // This is the new best possible length.
                        }
                    }
                } else {
                    potentialCandidates.clear();
                }

            }  /*  for (int cand=0; cand < candidates.size()...  */
            i += 2;
            candidates.addAll(potentialCandidates);
            System.out.printf("Processed %d characters. Candidate cookies:%n", i);
            for (StringBuilder sb: candidates) {
                System.out.println(sb);
            }
        }  /*  while (i < CHALLENGE51_COOKIE_LENGTH...  */

        assert  candidates.size() == 1 : "Too many possible cookies";
        return  candidates.get(0).substring(CHALLENGE51_COOKIE_NAME.length(), candidates.get(0).length());
    }

    @SneakyThrows
    public static byte[]  challenge56Oracle(String request) {
        KeyGenerator   rc4KeyGen = KeyGenerator.getInstance("RC4");
        rc4KeyGen.init(128);
        SecretKey  sk = rc4KeyGen.generateKey();
        Cipher  encryptor = Cipher.getInstance("RC4");

        encryptor.init(Cipher.ENCRYPT_MODE, sk);
        return  encryptor.doFinal(
                (request + CHALLENGE56_COOKIE + ", " + DatatypeConverter.printHexBinary(sk.getEncoded())).getBytes());
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
                    CHALLENGE50_TEXT, printHexBinary(trgtMac).toLowerCase());
            attackersMacedMsg = breakChallenge50(CHALLENGE50_TEXT.getBytes(), mac,
                    CHALLENGE50_TARGET_TEXT.getBytes(), encryptor.cipher.getBlockSize());
            mac = encryptor.generateCbcMac(attackersMacedMsg.getBytes(StandardCharsets.ISO_8859_1), encryptor.zeroedIV);
            System.out.printf("The CBC-MAC of %s%nis: %s%n",
                    attackersMacedMsg, printHexBinary(mac).toLowerCase());
            assert  Arrays.equals(trgtMac, mac);

            ScriptEngineManager   manager = new ScriptEngineManager();
            ScriptEngine   engine = manager.getEngineByName("JavaScript");
            engine.eval(attackersMacedMsg);

            System.out.println("\nChallenge 51");
            System.out.printf("Recovered sessionid for CTR Oracle is: %s%n", breakChallenge51(encryptor::challenge51OracleCTR));
            System.out.printf("Recovered sessionid for CBC Oracle is: %s%n", breakChallenge51(encryptor::challenge51OracleCBC));

            System.out.println("\nChallenge 52");
            String   msg = "test message";
            byte[]   H = { 0, 1 },  H2 = { 0, 1, 2, 3 };

            MDHelper  mdHelper = new MDHelper(H, H2, "Blowfish", 8);
            byte   hash[] = mdHelper.mdEasy(msg.getBytes());
            System.out.printf("The hash of '%s' is %s%n", msg, printHexBinary(hash));
            byte   collision[][] = mdHelper.findCollision();
            if (collision != null) {
                System.out.printf("Collision found between:%n\t%s%n\t%s%n%s%n",
                        printHexBinary(collision[0]), printHexBinary(collision[1]),
                        printHexBinary(mdHelper.mdHard(collision[0])));
                assert  Arrays.equals(mdHelper.mdHard(collision[0]), mdHelper.mdHard(collision[1]));
            }

            System.out.println("\nChallenge 53");
            collision = mdHelper.findCollision(4);
            if (collision != null) {
                System.out.printf("Collision found between:%n\t%s%n\t%s%n%s%n",
                        printHexBinary(collision[0]), printHexBinary(collision[1]),
                        printHexBinary(collision[2]));
                assert  Arrays.equals(mdHelper.mdInnerLast(collision[0], H, 0, 1),
                                      mdHelper.mdInnerLast(collision[1], H, 0, 9));
            }

            // Needs to be not much less than 2^16 blocks long
            byte[]   longMsg = new byte[Long.BYTES * 0x10000],  secondPreimage;
            new SecureRandom().nextBytes(longMsg);
            secondPreimage = mdHelper.find2ndPreimage(longMsg);
            assert  Arrays.equals(mdHelper.mdEasy(longMsg), mdHelper.mdEasy(secondPreimage));
            System.out.printf("Second preimage of %s found:%n%s%nThe original was:%n%s%n",
                    printHexBinary(Arrays.copyOf(mdHelper.mdEasy(longMsg), 256)),
                    printHexBinary(Arrays.copyOf(secondPreimage, 256)),
                    printHexBinary(Arrays.copyOf(longMsg, 256)));

            System.out.println("\nChallenge 54");
            String   originalCommittedToMsg = /* 15 blocks, 2^11 */
                    "3-5, 0-0, 1-6, 4-2, 2-2, 4-3, 1-1 dummy prediction that will be replaced"
                            + "123456788765432101234567765432101234567876543210"
                            /*+ "12345678"*/,
                     nostradamusMsg = "3-1, 0-1, 2-6, 2-2, 3-1, 1-1,0-3"; /* 4 blocks */
                   // "1-2, 3-1, 4-6, 2-0, 3-1, 1-1,0-3";  2^14
            hash = mdHelper.mdEasy(originalCommittedToMsg.getBytes());
            byte[]   trgtHash = mdHelper.mdInnerLast(originalCommittedToMsg.getBytes(), H,
                    0, originalCommittedToMsg.length() / 8),  sfx;
            DiamondStructure ds = new DiamondStructure(
                    originalCommittedToMsg.length() - nostradamusMsg.length() >> 3,
                    trgtHash, "Blowfish", 8);

            sfx = ds.constructSuffix(mdHelper.mdInnerLast(nostradamusMsg.getBytes(), H, 0, 4));
            if (sfx != null) {
                assert originalCommittedToMsg.length() == nostradamusMsg.length() + sfx.length;
                longMsg = Arrays.copyOf(nostradamusMsg.getBytes(), nostradamusMsg.length() + sfx.length);
                System.arraycopy(sfx, 0, longMsg, nostradamusMsg.length(), sfx.length);
                assert Arrays.equals(hash, mdHelper.mdEasy(longMsg));
                System.out.printf("Original message: %s%nOriginal message hash: %s%n"
                    + "Nostradamus message: %s%nNostradamus message hash:%s%n",
                        originalCommittedToMsg, printHexBinary(hash),
                        new String(longMsg), printHexBinary(mdHelper.mdEasy(longMsg)));
            } else {
                System.out.println("Too few leaves in the diamond structure :-(");
            }

            System.out.println("\nChallenge 55\n");
            collision = MD4CollisionsFinder.findCollision();
            System.out.printf("Collision found between%n\t%s%n\t%s%nMD4: %s%n",
                    printHexBinary(collision[0]), printHexBinary(collision[1]), printHexBinary(collision[2]));

            System.out.println("\nChallenge 56\n");
            byte[]  recoveredCookie = new RC4SingleByteBiasAttackHelper().recoverCookie(Set7::challenge56Oracle, CHALLENGE56_COOKIE.length());
            assert  Arrays.equals(recoveredCookie, CHALLENGE56_COOKIE.getBytes());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
