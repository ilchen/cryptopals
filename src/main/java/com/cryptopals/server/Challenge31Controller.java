package com.cryptopals.server;

import com.cryptopals.Set1;
import com.cryptopals.Set4;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Arrays;

@Controller
@RequestMapping("/")
public class Challenge31Controller {
    private final Set4   encryptor;
    private final long   delayMillis;
    private final int    signLen;

    Challenge31Controller(Set4 encr, Long delay, Integer signLength) {
        encryptor = encr;   delayMillis = delay;   signLen = signLength;
    }

    @GetMapping(value = "/test", params = { "file", "signature" })
    @ResponseStatus(value = HttpStatus.OK)
    public ResponseEntity<?> checkSignature(@RequestParam String file,
                                            @RequestParam("signature") String hmac) {
        return  new ResponseEntity<>(
                insecureCompare(Arrays.copyOf(encryptor.hmacSha1(file.getBytes()), signLen), Set1.parseHexBinary(hmac))
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
