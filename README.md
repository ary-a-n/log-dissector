# Log Analysis Script

This Python script analyzes a log file to extract key information, including:
- The number of requests per IP address.
- The most frequently accessed endpoint.
- Suspicious activity detection based on failed login attempts.

The results are displayed in the terminal and saved to a CSV file named `log_analysis_results.csv`.

## Features

- **Requests per IP**: Counts the number of requests made by each IP address.
- **Most Accessed Endpoint**: Identifies the most frequently accessed endpoint (e.g., `/home`).
- **Suspicious Activity**: Detects IP addresses with failed login attempts (HTTP status code `401`) exceeding a configurable threshold (default: 10 attempts).
- **CSV Export**: Saves the results in a CSV file with the following structure:
  - Requests per IP: `IP Address`, `Request Count`
  - Most Accessed Endpoint: `Endpoint`, `Access Count`
  - Suspicious Activity: `IP Address`, `Failed Login Count`

## Requirements

- Python 3.x
- `re` (for regular expressions)
- `collections.Counter` (for counting occurrences)

## Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/ary-a-n/log-dissector.git
   ```

2. Navigate to the project directory:

   ```bash
   cd log-analysis
   ```

3. Ensure Python 3.x is installed on your system. If not, install it from [here](https://www.python.org/downloads/).

## Usage

1. Place the log file (e.g., `sample.log`) in the same directory as the script.
2. Run the script using the following command:

   ```bash
   python log_analysis.py sample.log
   ```

   Replace `sample.log` with the path to your log file.

3. The script will:
   - Display the results in the terminal.
   - Save the results to `log_analysis_results.csv`.

### Example Output:

#### (Sample)Terminal Output:

```
IP Address        Request Count
========================================
192.168.1.1       234
203.0.113.5       187
10.0.0.2          92

Most Frequently Accessed Endpoint:
/home (Accessed 403 times)

Suspicious Activity Detected (IPs with failed login attempts > 10):
IP Address        Failed Login Count
========================================
192.168.1.1       15
203.0.113.5       12
```

#### CSV Output (`log_analysis_results.csv`):

```
Requests per IP
IP Address,Request Count
192.168.1.1,234
203.0.113.5,187
10.0.0.2,92

Most Accessed Endpoint
Endpoint,Access Count
/home,403

Suspicious Activity
IP Address,Failed Login Count
192.168.1.1,15
203.0.113.5,12
```

## Configuration

- **Threshold for Suspicious Activity**: The default threshold for flagging suspicious IPs is 10 failed login attempts. You can change this threshold by passing a second argument to the `main()` function.

  Example:

  ```bash
  python log_analysis.py sample.log 5
  ```

  This sets the threshold to 5 failed login attempts.

## Contributing

Feel free to fork the repository and submit pull requests.
