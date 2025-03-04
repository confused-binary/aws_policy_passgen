# AWS Policy Password Generator

A simple boi that just does a few things with creating passwords that meet AWS password policy requirements.

```
> $ python3 aws_pol_passgen.py --help
usage: aws_pol_passgen.py [-h] -file FILE [-key-words KEY_WORDS [KEY_WORDS ...]] [-max-words MAX_WORDS] [-max-length MAX_LENGTH]
                          [-max-duplicates MAX_DUPLICATES] [-loosey-dedup] [-simple-mutate] [-alpha-mutate]
                          [-require-length REQUIRE_LENGTH] [-require-upper REQUIRE_UPPER] [-require-lower REQUIRE_LOWER]
                          [-require-digit REQUIRE_DIGIT] [-require-special REQUIRE_SPECIAL] [-use-account-pass-pol USE_ACCOUNT_PASS_POL]
                          [-target-user TARGET_USER] [-target-days TARGET_DAYS]

Generate AWS-compliant passwords from wordlist.

options:
  -h, --help            show this help message and exit
  -file FILE            file containing key-words with one per line
  -key-words KEY_WORDS [KEY_WORDS ...]
                        Specify key words directly
  -max-words MAX_WORDS  Maximum words to combine
  -max-length MAX_LENGTH
                        Maximum password length
  -max-duplicates MAX_DUPLICATES
                        Maximum duplicate words in a password
  -loosey-dedup         Remove duplicates that appear in a password regardless of case.
  -simple-mutate        Add upper/lower capitalization of first character for each alpha.
  -alpha-mutate         Mutate all characters in each word for all lower/upper combinations.
  -require-length REQUIRE_LENGTH
                        Minimum password count
  -require-upper REQUIRE_UPPER
                        Minimum upper-case count
  -require-lower REQUIRE_LOWER
                        Minimum lower-case count
  -require-digit REQUIRE_DIGIT
                        Minimum digit count
  -require-special REQUIRE_SPECIAL
                        Minimum special character count
  -use-account-pass-pol USE_ACCOUNT_PASS_POL
                        Pull password policy from AWS profile (will override other 'require' arguments.)
  -target-user TARGET_USER
                        Create password combos using provided words and replacing year and season relevant to when they last changed
                        their password (requires -use-account-pass-pol as well and will remove other years/seasons from key-words list)
  -target-days TARGET_DAYS
                        Same as -target-user, but you specify the number of days. (Will remove other years/seasons from key-words list
```
