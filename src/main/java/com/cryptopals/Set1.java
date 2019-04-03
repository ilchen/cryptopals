package com.cryptopals;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;

import lombok.Builder;
import lombok.Data;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.util.stream.Collectors;

public class Set1 {
    static final int   AES_BLOCK_SIZE = 16;
    static final SecretKeySpec   YELLOW_SUBMARINE_SK = new SecretKeySpec("YELLOW SUBMARINE".getBytes(), "AES");
    enum Encoding {
        BASE64,  HEX
    }

    static String challenge1(String hex) {
        return DatatypeConverter.printBase64Binary(DatatypeConverter.parseHexBinary(hex));
    }

    public static byte[] challenge2(byte buf1[], byte buf2[]) {
        assert buf1.length == buf2.length;
        byte   res[] = new byte[buf1.length];
        for (int i=0; i < buf1.length; i++) {
            res[i] = (byte) (buf1[i] ^ buf2[i]);
        }
        return  res;
    }

    @Data @Builder
    static class FrequencyAnalysisHelper {
        final private byte   possiblePlainText[];
        final private float  score;
        final private char   key;
    }

    @Data @Builder
    static class FrequencyAnalysisReportingHelper {
        final private FrequencyAnalysisHelper candInfo;
        final private int         line;
        final private String      cipherText;
    }

    private static Map<Character, Float>   charFreqs;
    static {
        charFreqs = new TreeMap<>();
        charFreqs.put('a', .08167f);     charFreqs.put('b', .01492f);     charFreqs.put('c', .02782f);
        charFreqs.put('d', .04253f);     charFreqs.put('e', .12702f);     charFreqs.put('f', .02228f);
        charFreqs.put('g', .02015f);     charFreqs.put('h', .06094f);     charFreqs.put('i', .06094f);
        charFreqs.put('j', .00153f);     charFreqs.put('k', .00772f);     charFreqs.put('l', .04025f);
        charFreqs.put('m', .02406f);     charFreqs.put('n', .06749f);     charFreqs.put('o', .07507f);
        charFreqs.put('p', .01929f);     charFreqs.put('q', .00095f);     charFreqs.put('r', .05987f);
        charFreqs.put('s', .06327f);     charFreqs.put('t', .09056f);     charFreqs.put('u', .02758f);
        charFreqs.put('v', .00978f);     charFreqs.put('w', .02360f);     charFreqs.put('x', .00150f);
        charFreqs.put('y', .01974f);     charFreqs.put('z', .00074f);     charFreqs.put(' ', .13000f);
        charFreqs = Collections.unmodifiableMap(charFreqs);
    }

    static FrequencyAnalysisHelper challenge3Helper(byte cypherText[]) {
        //char   start = ' ',  end = '~';
        char   start = 0,  end = 255;
        byte   res[] = new byte[cypherText.length];
        SortedMap<Float, Character>   keyCands = new TreeMap<>();
        for (char ch = start; ch <= end; ch++) {
            float   score = 0f;
            for (int i = 0; i < cypherText.length; i++) {
                res[i] = (byte) (cypherText[i] ^ ch);
                char   ch2 = Character.toLowerCase((char) res[i]);
                //if (Character.isLetterOrDigit(ch2) || Character.isSpaceChar(ch2)) score += 1;
                score += charFreqs.getOrDefault(ch2, 0f);
            }
            keyCands.put(score, ch);  // potential other key will be discarded
        }

        char   key = keyCands.get(keyCands.lastKey());
        for (int i = 0; i < cypherText.length; i++)  res[i] = (byte) (cypherText[i] ^ key);
        return  new FrequencyAnalysisHelper(res, keyCands.lastKey(), key);
    }

    private static void challenge3(byte cypherText[]) {
        FrequencyAnalysisHelper res = challenge3Helper(cypherText);
        System.out.printf("%nkey: %c -> %s%n", res.getKey(), new String(res.getPossiblePlainText()));
    }


    static List<FrequencyAnalysisReportingHelper> challenge4(String url) throws IOException {
        SortedMap<Float, List<Integer>>   candsScores = new TreeMap<>();
        final int   maxLines = 600;
        final String   candidates[] = new String[maxLines];
        List<Integer>   collisions;
        FrequencyAnalysisHelper helper;
        String   line;
        try (InputStream is = new URL(url).openStream(); BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            for (int i=0; i < maxLines  &&  (line = reader.readLine()) != null; i++)  {
                candidates[i] = line;
                helper = challenge3Helper(DatatypeConverter.parseHexBinary(line));
                collisions = candsScores.computeIfAbsent(helper.getScore(), k -> new ArrayList<>());
                collisions.add(i);
            }
        }

        collisions = candsScores.get(candsScores.lastKey());
        return  collisions.stream().map(i -> new FrequencyAnalysisReportingHelper(
                challenge3Helper(DatatypeConverter.parseHexBinary(candidates[i])), i, candidates[i]))
                .collect(Collectors.toList());

    }

    private static byte[] challenge5Helper(byte plainTxt[], String key) {
        byte[]   k = key.getBytes(),  cypherTxt = new byte[plainTxt.length];
        for (int i=0, j=0; i < plainTxt.length; i++, j = i % k.length) {
            cypherTxt[i] = (byte) (plainTxt[i] ^ k[j]);
        }
        return  cypherTxt;
    }

    static byte[] challenge5(String plainText, String key) {
        return  challenge5Helper(plainText.getBytes(), key);
    }

    private static int  hammingDistance(String str1, String str2) {
        byte  xor[] = challenge2(str1.getBytes(), str2.getBytes());
        int   res = 0;
        for (byte b : xor) res += Integer.bitCount(b);
        return  res;
    }

    private static List<Integer>  findProbableKeySizes(String sb, int maxTries) {
        SortedMap<Float, List<Integer>>   dist2keySize = new TreeMap<>();
        for (int kSize=2; kSize < 41; kSize++) {
            float  distance =
                    (hammingDistance(sb.substring(0, kSize), sb.substring(kSize, kSize << 1))
                    + hammingDistance(sb.substring(kSize << 1, kSize * 3), sb.substring(kSize * 3, kSize << 2))
                    + hammingDistance(sb.substring(kSize << 2, kSize * 5), sb.substring(kSize * 5, kSize * 6))
                    + hammingDistance(sb.substring(kSize * 6, kSize * 7), sb.substring(kSize * 7, kSize << 3)))
                            / (float) (kSize << 2);
            dist2keySize.computeIfAbsent(distance, k -> new ArrayList<>()).add(kSize);
        }
        List<Integer>   res = new ArrayList<>(maxTries);
        int   i = 0;
        for (List<Integer> value : dist2keySize.values()) {
            res.addAll(value);    i += value.size();
            if (i >= maxTries)  break;
        }
        return  res.size() <= maxTries  ?  res : res.subList(0, maxTries);
    }


    private static byte[][]  getBlocks(byte fileBytes[], int kSize) {
        byte   ret[][] = new byte[kSize][];
        for (int i=0; i < kSize; i++) {
            int   remainder = fileBytes.length % kSize,  len = fileBytes.length / kSize;
            if (remainder > 0  &&  i < remainder)  len++;
            ret[i] = new byte[len];
            for (int j = i,  k = 0; j < fileBytes.length; j += kSize, k++)  ret[i][k] = fileBytes[j];
        }
        return  ret;
    }

    static byte[]  readFile(String url, Encoding enc) throws IOException {
        byte   fileBytes[];
        try (InputStream is = new URL(url).openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is));
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            String line;
            Function<String, byte[]>   encoder = enc == Encoding.BASE64  ?  DatatypeConverter::parseBase64Binary
                                                                         :  DatatypeConverter::parseHexBinary;
            while ((line = reader.readLine()) != null) {
                byte   next[] = encoder.apply(line);
                out.write(next, 0, next.length);
            }
            fileBytes = out.toByteArray();
        }
        return  fileBytes;
    }

    static List<byte[]>  readFileLines(String url, Encoding enc) throws IOException {
        List<byte[]>   blocks = new ArrayList<>();
        try (InputStream is = new URL(url).openStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            String line;
            Function<String, byte[]>   encoder = enc == Encoding.BASE64  ?  DatatypeConverter::parseBase64Binary
                    :  DatatypeConverter::parseHexBinary;
            while ((line = reader.readLine()) != null) {
                byte   next[] = encoder.apply(line);
                blocks.add(next);
            }
        }
        return  blocks;
    }

    @Data @Builder
    static class VigenereCipherAttackReporter {
        final private int     keySize;
        final private String  key,  plainText;
    }

    static List<VigenereCipherAttackReporter>  challenge6(String url) throws IOException {
        byte   fileBytes[] = readFile(url, Encoding.BASE64);
        List<VigenereCipherAttackReporter> res = new ArrayList<>();
        for (int kSize : findProbableKeySizes(new String(fileBytes), 5)) {
            System.out.printf("%n%nTrying key size %02d%n", kSize);
            byte blocks[][] = getBlocks(fileBytes, kSize);
            StringBuilder sb = new StringBuilder(kSize);
            for (int i = 0; i < kSize; i++) {
                FrequencyAnalysisHelper helper = challenge3Helper(blocks[i]);
                sb.append(helper.getKey());
            }
            String plainText = new String(challenge5Helper(fileBytes, sb.toString()));
            res.add(VigenereCipherAttackReporter.builder().keySize(kSize).key(sb.toString())
                    .plainText(plainText).build());
            System.out.printf("key: %s%nplain text:%n%s", sb.toString(), plainText);
        }
        return  res;
    }

    static byte[] challenge7(String url) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher   aes = Cipher.getInstance("AES/ECB/PKCS5Padding"); /* The Cipher engine will deal with padding */
        aes.init(Cipher.DECRYPT_MODE, YELLOW_SUBMARINE_SK);
        byte   fileBytes[] = readFile(url, Encoding.BASE64);
        return  aes.doFinal(fileBytes);
    }

    static int  countUniqueCipherBlocks(byte cipherText[], int blockSize) {
        Set<ByteBuffer>   uniqueBlocks = new HashSet<>();
        for (int j=0; j < cipherText.length; j += blockSize) {
            // We need a type that properly wraps 'blockSize' bytes and whose equals and hashCode would work properly,
            // 'ByteBuffer' fills the bill.
            uniqueBlocks.add(ByteBuffer.wrap(Arrays.copyOfRange(cipherText, j, j + blockSize)));
        }
        return  uniqueBlocks.size();
    }

    static FrequencyAnalysisReportingHelper  challenge8(String url) throws IOException {
        List<byte[]>  ciphertexts = readFileLines(url, Encoding.HEX);
        SortedMap<Integer, Integer>   uniqueVals2lines = new TreeMap<>();
        int   numCiphertexts = ciphertexts.size();
        for (int i=0; i < numCiphertexts; i++) {
            uniqueVals2lines.put(countUniqueCipherBlocks(ciphertexts.get(i), AES_BLOCK_SIZE), i);
        }
        int      lineNum = uniqueVals2lines.get(uniqueVals2lines.firstKey());
        String   cipherText = DatatypeConverter.printHexBinary(ciphertexts.get(lineNum));
        return  FrequencyAnalysisReportingHelper.builder().line(lineNum).cipherText(cipherText).build();
    }

    static void suppressSSLServerCertificateChecks() throws NoSuchAlgorithmException, KeyManagementException {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {  }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {  }
                }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        // Create all-trusting host name verifier
        HostnameVerifier allHostsValid = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        // Install the all-trusting host verifier
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    public static void main(String[] args) {

        String   hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        System.out.printf("hex: %s is%nbase64: %s", hex, challenge1(hex));

        hex = "1c0111001f010100061a024b53535009181c";
        String   hex2 = "686974207468652062756c6c277320657965";

        System.out.printf("%n%s xored with %s gives%n%s", hex, hex2, DatatypeConverter.printHexBinary(
                challenge2(DatatypeConverter.parseHexBinary(hex), DatatypeConverter.parseHexBinary(hex2))));

        hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

        challenge3(DatatypeConverter.parseHexBinary(hex));


        try {
            // Import DST Root CA X3 certificate into $JAVA_HOME/jre/lib/security/cacerts or uncomment the next line
            // suppressSSLServerCertificateChecks();
            List<FrequencyAnalysisReportingHelper>  cands = challenge4("https://cryptopals.com/static/challenge-data/4.txt");
            for(FrequencyAnalysisReportingHelper cand : cands) {
                System.out.printf("%nline #%02d\tscore: %02f%n%s%nkey: %c -> %s%n", cand.getLine(),
                        cand.getCandInfo().getScore(), cand.getCipherText(), cand.getCandInfo().getKey(),
                        new String(cand.getCandInfo().getPossiblePlainText()));
            }

            hex = "Burning 'em, if you ain't quick and nimble\n" + "I go crazy when I hear a cymbal";
            hex2 = "ICE";
            System.out.printf("Challenge 5%nPlain text: %s, key: %s%nCypher text: %s%n",
                    hex, hex2, DatatypeConverter.printHexBinary(challenge5(hex, hex2)).toLowerCase());


            System.out.println("\nChallenge 6");
            System.out.printf("Hamming distance between '%s' and '%s' is %2d%n", "this is a test", "wokka wokka!!!",
                    hammingDistance("this is a test", "wokka wokka!!!"));

            challenge6("https://cryptopals.com/static/challenge-data/6.txt");
            byte  plainText[] = challenge7("https://cryptopals.com/static/challenge-data/7.txt");
            System.out.printf("%nChallenge 7%nPlain text:%n%s", new String(plainText));

            FrequencyAnalysisReportingHelper  res = challenge8("https://cryptopals.com/static/challenge-data/8.txt");
            System.out.printf("%nChallenge 8%nThe most likely ciphertext encoded in AES ECB is cyphertext #%02d:%n%s",
                    res.getLine(), res.getCipherText());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
