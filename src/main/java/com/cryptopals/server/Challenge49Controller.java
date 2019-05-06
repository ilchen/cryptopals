package com.cryptopals.server;

import com.cryptopals.Set7;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.text.NumberFormat;
import java.util.Locale;
import java.util.Map;

@Controller
@RequestMapping("/challenge49")
public class Challenge49Controller {
    private Map<String, SecretKey>   headerToKeyMap;
    private NumberFormat   currencyFormatter;

    @Autowired
    Challenge49Controller(Map<String, SecretKey>  h2keyMap) {
        headerToKeyMap = h2keyMap;
        currencyFormatter = NumberFormat.getCurrencyInstance(Locale.US);
    }

    @PostMapping(value = "/sct", params = { "from", "to", "amount" }, headers = { "userid" })
    public ResponseEntity<?> checkSignature(@RequestParam("from") String from,
                                            @RequestParam("to") String to,
                                            /*@RequestParam("amount") String amount, easier to extract it from the qs */
                                            @RequestHeader("userid") String userId,
                                            HttpServletRequest request) {
        try {
            /*System.out.printf("Entered checkSignature%nfrom: %s%nto: %s%nuserid: %s%nqs: %s%n",
                    from, to, userId, request.getQueryString());*/
            SecretKey key = headerToKeyMap.get(userId);
            if (key == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            Set7 encryptor = new Set7(Cipher.ENCRYPT_MODE, key);
            String qs = encryptor.validateCreditTransferMsg(request.getQueryString());
            if (qs.equals("")) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            BigDecimal amt = new BigDecimal(qs.substring(qs.lastIndexOf("amount=") + 7));
            System.out.printf("On request of user %s transferring %s from %s to %s%n",
                    userId, currencyFormatter.format(amt.doubleValue()), from, to);
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        } catch (NumberFormatException e) {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping(value = "/mct", params = { "from" , "tx_list" }, headers = { "userid" })
    public ResponseEntity<?> checkSignatureMct(@RequestParam("from") String from,
                                               @RequestParam(name="tx_list") String txLists[],
                                               @RequestHeader("userid") String userId/*,
                                               HttpServletRequest request*/) {
        try {
/*            System.out.printf("Entered checkSignatureMct%nfrom: %s%ntx_list: %s%nuserid: %s%nqs: %s%n",
                    from, Arrays.toString(txLists), userId, request.getQueryString());*/
            SecretKey key = headerToKeyMap.get(userId);
            if (key == null) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            Set7 encryptor = new Set7(Cipher.ENCRYPT_MODE, key);
            StringBuilder  sb = new StringBuilder("from=").append(from);
            for (String txList : txLists) {
                sb.append("&tx_list=").append(txList);
            }
//            System.out.println("Reconstructed query string:\n" + sb);
            String qs = encryptor.validateMultipleCreditTransferMsg(sb.toString());
//          String qs = encryptor.validateMultipleCreditTransferMsg(request.getQueryString());
            if (qs.equals("")) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }
            String txList = qs.substring(qs.lastIndexOf("tx_list=") + 8);
            String   txs[] = txList.split(";");
            System.out.printf("On request of user %s transferring:%n", userId);
            for (String tx : txs) {
                int   colonIdx = tx.indexOf(':');
                BigDecimal amt = new BigDecimal(tx.substring(colonIdx + 1, tx.length()));
                System.out.printf("\t%s to %s%n", currencyFormatter.format(amt.doubleValue()), tx.substring(0, colonIdx));
            }
            return new ResponseEntity<>(HttpStatus.ACCEPTED);
        } catch (NumberFormatException e) {
            return new ResponseEntity<>(HttpStatus.EXPECTATION_FAILED);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
