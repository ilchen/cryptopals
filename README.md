# cryptopals
Solutions to https://cryptopals.com problems

The only dependency on top of standard JRE 8 runtime is that on Lombok https://projectlombok.org

For Challenge 48 there's a dependency on https://github.com/square/jna-gmp/tree/master/jnagmp, which is a wrapper
around gmp 6.1.x. If you are on macOS, you probably already installed gmp when you installed python using brew. With
JRE's BigInteger Challenge 48 will take around 5 hours to finish. Using gmp it finishes under 1 hour.
