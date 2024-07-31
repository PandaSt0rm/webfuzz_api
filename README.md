# API Fuzzer

API Fuzzer is a Python tool designed for security testing and discovering valid endpoints in web applications by fuzzing API endpoints using a wordlist. It is built to efficiently handle and retry failed requests, log unusual response statuses, and save the discovered endpoints for further examination.

It was created to demonstrate a simple codebase to automate the fuzzing process for a the "Web Fuzzing" HTB Module.

## Installation

This project requires Python 3.6+ with the `requests` and `colorama` libraries. Install the required libraries using pip:

```bash
pip install requests colorama
```

or

```bash
pip install -r requirements.txt
```

## Usage

To use API Fuzzer, you need to specify the base URL of the API you want to test. Optionally, you can customize several parameters like wordlist path, rate limit, headers, and request timeout.

```bash
python api_fuzzer.py http://example.com/api
```

### Options

- `--wordlist`: Path to the wordlist for fuzzing endpoints. If omitted, a default wordlist will be loaded.
- `--rate-limit`: Limits the rate of requests per second. Default is no limit.
- `--headers`: Custom headers to use in requests, in JSON format.
- `--timeout`: Timeout for each request in seconds. Default is 10 seconds.
- `--output`: File path to save discovered valid endpoints.
- `-o`: Quick save to `discovered_endpoints.txt`.

```bash
python api_fuzzer.py http://example.com/api --wordlist ./path/to/wordlist.txt --rate-limit 10 --headers '{"Content-Type": "application/json"}' --timeout 5 --output results.txt
```
