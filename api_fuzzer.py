import requests
import argparse
import urllib.parse
import time
import json
from colorama import Fore, Style, init
from typing import Dict
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry


class EndpointFuzzer:
    """
    A class representing an endpoint fuzzer.

    Attributes:
        base_url (str): The base URL of the API.
        wordlist_path (str): The path to the wordlist file.
        rate_limit (float): The rate limit for sending requests.
        headers (Dict[str, str]): The headers to be included in the requests.
        timeout (int): The timeout for each request.
        discovered_endpoints (List[str]): A list of discovered valid endpoints.
        unusual_endpoints (List[Tuple[str, int]]): A list of endpoints with unusual status codes.
        total_requests (int): The total number of requests sent.
        failed_requests (int): The number of failed requests.
        retries (int): The number of retries for failed requests.
        status_code_counts (Dict[int, int]): A dictionary mapping status codes to their counts.
        session (requests.Session): The session object for making HTTP requests.

    Methods:
        create_session(): Creates and configures a session object for making HTTP requests.
        increment_retries(): Increments the number of retries for failed requests.
        load_wordlist(): Loads the wordlist from a file or fetches it remotely.
        load_remote_wordlist(): Fetches the wordlist from a remote URL.
        fuzz_endpoints(): Starts the fuzzing process by iterating over the wordlist and testing each endpoint.
        test_endpoint(endpoint: str): Tests a single endpoint by sending a GET request and analyzing the response.
        print_summary(): Prints a summary of the fuzzing results.
        save_results(output_file: str): Saves the discovered valid endpoints to a file.

    """

    def __init__(
        self,
        base_url: str,
        wordlist_path: str = None,
        rate_limit: float = None,
        headers: Dict[str, str] = None,
        timeout: int = 10,
    ):
        self.base_url = base_url
        self.wordlist_path = wordlist_path
        self.rate_limit = rate_limit
        self.headers = headers if headers else {}
        self.timeout = timeout
        self.discovered_endpoints = []
        self.unusual_endpoints = []
        self.total_requests = 0
        self.failed_requests = 0
        self.retries = 0
        self.status_code_counts = {}
        init(autoreset=True)
        self.session = self.create_session()

    def create_session(self):
        """
        Creates and configures a session object for making HTTP requests.

        Returns:
            requests.Session: The configured session object.
        """
        session = requests.Session()
        retry_strategy = Retry(
            total=5,
            backoff_factor=0.1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def increment_retries(self):
        """
        Increments the number of retries for failed requests.
        """
        self.retries += 1

    def load_wordlist(self):
        """
        Loads the wordlist from a file or fetches it remotely.

        Returns:
            List[str]: The list of words from the wordlist.
        """
        if self.wordlist_path:
            with open(self.wordlist_path, "r") as f:
                words = f.read().splitlines()
            print(f"{Fore.CYAN}Loaded wordlist from {self.wordlist_path}.")
        else:
            words = self.load_remote_wordlist()
        return words

    def load_remote_wordlist(self):
        """
        Fetches the wordlist from a remote URL.

        Returns:
            List[str]: The list of words from the remote wordlist.
        """
        seclists_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        print(f"{Fore.CYAN}Fetching remote wordlist from {seclists_url}...")
        try:
            response = self.session.get(seclists_url)
            response.raise_for_status()
            words = response.text.splitlines()
            print(f"{Fore.GREEN}Successfully fetched remote wordlist.")
        except requests.RequestException as e:
            print(f"{Fore.RED}Failed to fetch remote wordlist: {e}")
            words = []
        return words

    def fuzz_endpoints(self):
        """
        Starts the fuzzing process by iterating over the wordlist and testing each endpoint.
        """
        wordlist = self.load_wordlist()
        print(f"{Fore.CYAN}Starting fuzzing with {len(wordlist)} words.")
        delay = 1 / self.rate_limit if self.rate_limit else 0
        for word in wordlist:
            self.test_endpoint(word)
            if delay:
                time.sleep(delay)
        self.print_summary()

    def test_endpoint(self, endpoint: str):
        """
        Tests a single endpoint by sending a GET request and analyzing the response.

        Args:
            endpoint (str): The endpoint to test.
        """
        full_url = urllib.parse.urljoin(self.base_url, endpoint)
        try:
            response = self.session.get(
                full_url, headers=self.headers, timeout=self.timeout
            )
            self.total_requests += 1
            if response.status_code in [500, 502, 503, 504]:
                self.increment_retries()
            status_code = response.status_code
            self.status_code_counts[status_code] = (
                self.status_code_counts.get(status_code, 0) + 1
            )
            if status_code == 200:
                print(
                    f"{Fore.GREEN}[+] Valid endpoint found: {full_url} (Status code: {status_code})"
                )
                self.discovered_endpoints.append(full_url)
            elif status_code != 404:
                print(
                    f"{Fore.MAGENTA}[!] Unusual status code for {full_url} (Status code: {status_code})"
                )
                self.unusual_endpoints.append((full_url, status_code))
            else:
                print(
                    f"{Fore.YELLOW}[-] Invalid endpoint: {full_url} (Status code: {status_code})"
                )
        except requests.RequestException as e:
            self.total_requests += 1
            self.failed_requests += 1
            print(f"{Fore.RED}[!] Request failed for {full_url}: {e}")

    def print_summary(self):
        """
        Prints a summary of the fuzzing results.
        """
        print(f"\n{Fore.CYAN}Fuzzing completed.")
        print(f"{Fore.CYAN}Total requests: {self.total_requests}")
        print(f"{Fore.RED}Failed requests: {self.failed_requests}")
        print(f"{Fore.YELLOW}Retries: {self.retries}")
        print(f"{Fore.CYAN}Status code counts:")
        for status_code, count in self.status_code_counts.items():
            print(f"{Fore.CYAN}{status_code}: {count}")

        if self.discovered_endpoints:
            print(f"{Fore.GREEN}Found valid endpoints:")
            for endpoint in self.discovered_endpoints:
                print(f"{Fore.GREEN}- {endpoint}")
        else:
            print(f"{Fore.RED}No valid endpoints found.")

        if self.unusual_endpoints:
            print(f"{Fore.MAGENTA}Unusual status codes:")
            for endpoint, status_code in self.unusual_endpoints:
                print(f"{Fore.MAGENTA}{status_code}: {endpoint}")

    def save_results(self, output_file: str):
        """
        Saves the discovered valid endpoints to a file.

        Args:
            output_file (str): The path to the output file.
        """
        if output_file:
            with open(output_file, "w") as f:
                for endpoint in self.discovered_endpoints:
                    f.write(f"{endpoint}\n")
            print(f"{Fore.CYAN}Results saved to {output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fuzzer for discovering valid endpoints using a wordlist."
    )
    parser.add_argument("base_url", nargs="?", help="Base URL of the API to test.")
    parser.add_argument(
        "--wordlist",
        help="Path to the wordlist for fuzzing endpoints. If no wordlist is provided, it will load SecList's common.txt wordlist automatically.",
        default=None,
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        help="Rate limit for requests (requests per second).",
        default=None,
    )
    parser.add_argument(
        "--headers",
        type=str,
        help="Custom headers for requests (JSON format).",
        default=None,
    )
    parser.add_argument(
        "--timeout", type=int, help="Timeout for requests (seconds).", default=10
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", help="File to save discovered endpoints.")
    group.add_argument(
        "-o", action="store_true", help="Quick save to discovered_endpoints.txt"
    )
    args = parser.parse_args()

    if not args.base_url:
        parser.print_help()
        parser.exit()

    headers = json.loads(args.headers) if args.headers else None

    fuzzer = EndpointFuzzer(
        base_url=args.base_url,
        wordlist_path=args.wordlist,
        rate_limit=args.rate_limit,
        headers=headers,
        timeout=args.timeout,
    )
    fuzzer.fuzz_endpoints()
    output_file = "discovered_endpoints.txt" if args.o else args.output
    fuzzer.save_results(output_file)
