# BruteCookie

### Introduction

BruteCookie is a very simple and fast cookie brute-forcing tool that bruteforces cookie values (from a wordlist) on a page, and filters out the erroneous responses to show which cookie value does not throw an error.

**The maximum number of concurrent threads is the maximum number of requests that will be sent simultaneously, so crank it up to get amazing speeds, while keeping in mind that more requests mean more chances of you getting blocked by the server.**

### Usage

```
usage: bruteCookie.py [-h] -u URL -c COOKIE [-ct COOKIE_TEMPLATE] [-cp COOKIE_PLACEHOLDER] -w WORDLIST
                      [-e {none,base64,url,hex}] -x EXCLUDE [-t THREADS] [-C OTHER_COOKIES] [-H CUSTOM_HEADERS]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     URL to bruteforce at
  -c COOKIE, --cookie COOKIE
                        The cookie name
  -ct COOKIE_TEMPLATE, --cookie-template COOKIE_TEMPLATE
                        The cookie-value template to use; use placeholder in place of the cookie-value's place;
                        default is FUZZ; example: "id=2&user=FUZZ"
  -cp COOKIE_PLACEHOLDER, --cookie-placeholder COOKIE_PLACEHOLDER
                        Cookie-value placeholder to use; default is FUZZ
  -w WORDLIST, --wordlist WORDLIST
                        Wordlist to use
  -e {none,base64,url,hex}, --encode-cookie {none,base64,url,hex}
                        Encoding to use for cookie-value; default is 'none'
  -x EXCLUDE, --exclude EXCLUDE
                        Strings to detect in error responses; format: "Access Denied"; use as many times as
                        needed
  -t THREADS, --threads THREADS
                        Max number of concurrent threads; default is 10
  -C OTHER_COOKIES, --other-cookies OTHER_COOKIES
                        Other cookies to include in requests; format: "cookiename=cookieval"; use as many times
                        as needed to include all cookies
  -H CUSTOM_HEADERS, --custom-headers CUSTOM_HEADERS
                        Include custom headers in reqests; format: "header=value of header"; use as many times
                        as needed to include all headers

```

### Author

Author: CaptainWoof

Twitter: [@realCaptainWoof](https://www.twitter.com/realCaptainWoof)

