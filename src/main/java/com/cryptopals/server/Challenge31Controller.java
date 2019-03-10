package com.cryptopals.server;

import com.cryptopals.Set4;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
@RequestMapping("/")
public class Challenge31Controller {
    private Set4   encryptor;
    private long   delayMillis;
    private int    signLen;

    @Autowired
    Challenge31Controller(Set4 encr, Long delay, Integer signLength) {
        encryptor = encr;   delayMillis = delay;   signLen = signLength;
    }

    @RequestMapping(value = "/test", params = { "file", "signature" }, method = GET)
    @ResponseStatus(value = HttpStatus.OK)
    public ResponseEntity<?> checkSignature(@RequestParam("file") String file,
                                            @RequestParam("signature") String hmac) {
        return  new ResponseEntity<>(
                insecureCompare(Arrays.copyOf(encryptor.hmacSha1(file.getBytes()), signLen), DatatypeConverter.parseHexBinary(hmac))
                    ?  HttpStatus.OK : HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private boolean  insecureCompare(byte expected[], byte act[]) {
        int   n = Math.min(act.length, expected.length),  i;
        try {
            for (i=0; i < n  &&  act[i] == expected[i]; i++, Thread.sleep(delayMillis));
            return  i == n  &&  n == expected.length;
        } catch (InterruptedException e) {
            return  false;
        }
    }

}
