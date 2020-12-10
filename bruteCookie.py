#!/usr/bin/python3

import requests
from argparse import ArgumentParser
from threading import Thread, Lock
from time import sleep
from base64 import b64encode
from urllib.parse import quote as url
from prettytable import PrettyTable


class BruteCookie:
    def __init__(self, u, c, w, x, t, C, H, ct, cp, ec):
        self.total_payloads = 0
        self.url = u
        self.cookiename = c
        self.wordlist_name = w
        self.exclude = x  # list of strings
        self.max_threads = t
        self.other_cookies = {}
        self.custom_headers = {}
        self.threads_list = []
        self.lock = Lock()
        self.requests_sent_in_one_sec = 0  # timely stat
        self.requests_to_display = 0  # timely stat
        self.total_payloads_sent = 0  # stat
        self.previous_line_size = 0
        self.isRunning = False
        self.longest_payload_length = 0
        self.found_results = 0
        self.cookie_template = ct
        self.cookie_placeholder = cp
        self.encode_cookie = ec

        if C is not None:
            for name_val in C:
                name = name_val.split("=")[0]
                val = name_val.split("=")[1]
                self.other_cookies[name] = val

        if H is not None:
            for header_val in H:
                header = header_val.split("=")[0]
                val = header_val.split("=")[1]
                self.other_cookies[header] = val

        try:
            self.wordlist = open(self.wordlist_name, 'r')
            print("\n[..] Counting payloads in wordlist for stats")
            for line in iter(self.wordlist.readline, ''):
                self.total_payloads += 1
                if len(line.strip()) > self.longest_payload_length:
                    self.longest_payload = line.strip()
                    self.longest_payload_length = len(line)
                cv = self.cookie_template.replace(self.cookie_placeholder, self.longest_payload)
                self.longest_payload_length = len(cv)
                if self.encode_cookie == 'base64':
                    ecv = b64encode(cv.encode()).decode()
                    line = '\r"' + cv + '" -> "' + ecv + '"'
                    self.longest_payload_length = len(line)
                elif self.encode_cookie == 'hex':
                    ecv = cv.encode().hex()
                    line = '\r"' + cv + '" -> "' + ecv + '"'
                    self.longest_payload_length = len(line)
                elif self.encode_cookie == 'url':
                    ecv = url(cv)
                    line = '\r"' + cv + '" -> "' + ecv + '"'
                    self.longest_payload_length = len(line)

            self.wordlist.seek(0, 0)
            print("\nCONFIGURATION\n-------------")
            print("[+] Total payloads loaded => " + str(self.total_payloads))
            print("[+] Cookie to bruteforce => '" + self.cookiename + "'")
            print("[+] Threads initialized => " + str(self.max_threads))
        except FileNotFoundError:
            print("[!] The wordlist provided was not found!")
            exit(0)

        except UnicodeDecodeError:
            print("[!] The wordlist provided contains some invalid characters!")
            exit(0)

        self.stat_counter_thread = Thread(target=self.statCounter)

    def start(self):
        print("\n")
        print("[+] BRUTEFORCING...")
        first_col = "Cookie Value"
        if len(first_col) < self.longest_payload_length:
            self.first_col_width = self.longest_payload_length
            header = first_col + ' ' * (self.longest_payload_length - len(first_col)) + '|' + ' ' * 2 + 'Response Code'
        else:
            self.first_col_width = len(first_col + ' '*2)
            header = first_col + ' ' * 2 + '|' + ' ' * 2 + 'Response Code'
        header += ' ' * 2 + '|' + ' ' * 2 + 'Response Size'

        print("-" * len(header))
        print(header)
        print("-" * len(header))

        self.isRunning = True
        self.stat_counter_thread.start()

        for thread_num in range(0, self.max_threads):
            thread = Thread(target=self.bruteforce,args=[])
            self.threads_list.append(thread)
            thread.start()

        for thread in self.threads_list:
            thread.join()

        self.isRunning = False
        self.stat_counter_thread.join()
        self.wordlist.close()

        print("\r" + " " * self.previous_line_size, end='')
        if self.found_results == 0:
            print("\n\n[!] No results found")
        else:
            print("\n\n[+] " + str(self.found_results) + " results found")
        return

    def close(self):
        self.isRunning = False
        for thread in self.threads_list:
            thread.join()

    # Thread function
    def bruteforce(self):
        while True:
            with self.lock:
                cookie_val = self.wordlist.readline().strip()

            if not cookie_val:
                return

            if not self.isRunning:
                return

            cookie_val = self.cookie_template.replace(self.cookie_placeholder, cookie_val)
            if self.encode_cookie == 'none':
                encoded_cookie_val = cookie_val
            elif self.encode_cookie == 'base64':
                encoded_cookie_val = b64encode(cookie_val.encode()).decode()
            elif self.encode_cookie == 'url':
                encoded_cookie_val = url(cookie_val)
            elif self.encode_cookie == 'hex':
                encoded_cookie_val = cookie_val.encode().hex()

            brutecookie_dict = {self.cookiename:encoded_cookie_val}
            brutecookie_dict.update(self.other_cookies)

            response = requests.get(self.url, headers=self.custom_headers, cookies=brutecookie_dict)
            self.requests_sent_in_one_sec += 1
            self.total_payloads_sent += 1
            body = response.text

            isFound = True
            for x in self.exclude:
                if x in body:
                    isFound = False
                    break

            with self.lock:
                if isFound:
                    self.found_results += 1
                    print('\r' + ' ' * self.previous_line_size, end='')
                    if self.encode_cookie == 'none':
                        line = '\r"' + cookie_val + '"'
                    else:
                        line = '\r"' + cookie_val + '" -> "' + encoded_cookie_val + '"'
                    if len(line) < self.first_col_width:
                        line += ' ' * (self.first_col_width - len(line) + 1)
                    line += '|  ' + str(response.status_code) + " "*12
                    line += '|  ' + str(len(response.text))
                    print(line)
                    self.previous_line_size = len(line)
                print('\r' + ' ' * self.previous_line_size, end='')

                if self.encode_cookie == 'none':
                    line = "\r'" + cookie_val + "'" + ' - ' + str(self.requests_to_display) + ' req/s - '
                    line += f"{((self.total_payloads_sent / self.total_payloads) * 100):.2f}" + ' %'
                else:
                    line = '\r"' + cookie_val + '" -> "' + encoded_cookie_val + '"'
                    line += ' - ' + str(self.requests_to_display) + ' req/s - '
                    line += f"{((self.total_payloads_sent / self.total_payloads) * 100):.2f}" + ' %'

                print(line, end='')
                self.previous_line_size = len(line)

    # Also threaded
    def statCounter(self):
        while True:
            sleep(1)
            self.requests_to_display = self.requests_sent_in_one_sec
            self.requests_sent_in_one_sec = 0
            if not self.isRunning:
                break
        return


description = "BruteCookie is a very simple and fast cookie brute-forcing tool "
description += "that bruteforces cookie values (from a wordlist) on a page, and "
description += "filters out the erroneous responses to show which cookie value "
description += "does not throw an error"

epilogue = "Author: CaptainWoof | Twitter: @realCaptainWoof"

parser = ArgumentParser(description=description, epilog=epilogue)
parser.add_argument('-u', '--url', action='store', type=str, required=True, help="URL to bruteforce at")
parser.add_argument('-c', '--cookie', action='store', type=str, required=True, help="The cookie name")
parser.add_argument('-ct', '--cookie-template', action='store', type=str, required=False,
                    default="FUZZ", help="The cookie-value template to use; use placeholder in place of "
                                         "the cookie-value's place; default is FUZZ; example: \"id=2&user=FUZZ\"")
parser.add_argument('-cp', '--cookie-placeholder', action='store', default='FUZZ', type=str,
                    required=False, help="Cookie-value placeholder to use; default is FUZZ")
parser.add_argument('-w', '--wordlist', action='store', type=str, required=True, help="Wordlist to use")
parser.add_argument('-e', '--encode-cookie', action='store', default='none', type=str,
                    choices=['none', 'base64', 'url', 'hex'], required=False,
                    help='Encoding to use for cookie-value; default is \'none\'')
parser.add_argument('-x', '--exclude', action='append', type=str, required=True,
                    help='Strings to detect in error responses; format: \"Access Denied\"; '
                         'use as many times as needed')
parser.add_argument('-t', '--threads', action='store', type=int, required=False, default=10,
                    help="Max number of concurrent threads; default is 10")
parser.add_argument('-C', '--other-cookies', action='append', type=str, required=False,
                    help="Other cookies to include in requests; format: \"cookiename=cookieval\"; "
                         "use as many times as needed to include all cookies", default=None)
parser.add_argument('-H', '--custom-headers', action='append', type=str, required=False,
                    help="Include custom headers in reqests; format: \"header=value of header\"; "
                         "use as many times as needed to include all headers", default=None)
argv = parser.parse_args()

try:
    bruteCookie = BruteCookie(argv.url, argv.cookie, argv.wordlist, argv.exclude, argv.threads,
                              argv.other_cookies, argv.custom_headers, argv.cookie_template, argv.cookie_placeholder
                              , argv.encode_cookie)
    bruteCookie.start()

except KeyboardInterrupt:
    try:
        bruteCookie.close()
    except:
        pass
    print("\r[!] All threads shutdown!")
