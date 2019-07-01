# cryptopals
Solutions to https://cryptopals.com problems

The only dependency on top of standard JRE 8 runtime is that on Lombok https://projectlombok.org

## Challenge 48
For [Challenge 48](https://cryptopals.com/sets/6/challenges/48) there's a dependency on https://github.com/square/jna-gmp/tree/master/jnagmp, which is a wrapper
around gmp 6.1.x. If you are on macOS, you probably already installed gmp when you installed python using brew. With
JRE's BigInteger Challenge 48 will take around 5 hours to finish. Using gmp it finishes under 1 hour.

## Challenge 55
[Challenge 55](https://cryptopals.com/sets/7/challenges/55) is probably one of the most interesting to work on.
I succeeded in implementing it in a uniform Object-Oriented way, which aids readability and maintainability.
The implementation is also blazingly fast -- it finds a collison within a few seconds. Here is one found with it:
```$xslt
Collision found between
	683E10B651E9185B4D9886D90B7634AE7C4D753533F75041C388E6ACF20CF8B12BA9C27368F09B22EDCE3445BBFED7E8636EDB70070DF0EB7449FA54E421D246
	683E10B651E918DB4D9886490B7634AE7C4D753533F75041C388E6ACF20CF8B12BA9C27368F09B22EDCE3445BBFED7E8636EDA70070DF0EB7449FA54E421D246
MD4: B9B0031B30D53E826B80CBDDBE7354D9
```
I succeeded in fully enforcing all constraints from the first round of MD4 as well as all constraints from the first two steps of the second round.
I didn't figure out how to apply the constraints from the 3rd step of the second round of MD4. X. Wang et al. give some
hints in their paper, yet they are not easy to follow
> Utilize more precise modification to correct some other conditions. For example, we can use the internal collision in Table 2 in which there are three message words are changed to correct c5,i, i = 26, 27, 29, 32. The precise modification should add some extra conditions in the first rounds (see Table 2) in advance. There are many other precise modifications.
c5,30 can be corrected by other modification. By various modifications, besides two conditions in the third round, almost all the conditions in rounds 1-2 will be corrected. The probability can be among 2^6 ∼ 2^2.
