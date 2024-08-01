Sure, here's a README file for the CLI tool:


# Traffic Analyzer CLI Tool

This tool analyzes website traffic logs to identify Google bots, bad bot traffic, and human traffic. It uses various signals to differentiate between legitimate and illegitimate traffic.

## Features

- **Identify Google bot traffic**: Detects legitimate Google bots based on user agent strings, IP addresses, and other signals.
- **Identify bad bot traffic**: Detects known bad bots, fake Google bots, and the use of libraries and net tools based on user agent strings and other signals.
- **Identify human traffic**: Filters out bot traffic to identify human traffic.

## Installation

1. Clone the repository or download the script.
2. Ensure you have Python 3.x installed.
3. Install required dependencies using pip:
    ```sh
    pip install pandas requests
    ```

## Usage

Run the script from the command line with the appropriate arguments:

```sh
python traffic_analyzer.py <file> [options]
```

### Arguments

- `<file>`: The CSV file containing the logs to analyze.

### Options

- `--googlebot`: Identify Google bot traffic.
- `--badbot`: Identify bad bot traffic.
- `--human`: Identify human traffic.

### Examples

Identify Google bot traffic:

```sh
python traffic_analyzer.py logs_analyst.csv --googlebot
```

Identify bad bot traffic:

```sh
python traffic_analyzer.py logs_analyst.csv --badbot
```

Identify human traffic:

```sh
python traffic_analyzer.py logs_analyst.csv --human
```

## Signals Used

### Google Bot Signals

1. User agent: `Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`
2. IP address: Starts with `66.249.`
3. `apiIpAutonomousSystemOrganization`: Contains `GOOGLE`
4. JavaScript WebGL Renderer, WebDriver, and Hardware Concurrency: Null or NaN
5. `apiEndpoint`: Must be `http`
6. `fingerprintAccept`: Contains `text/html`

### Bad Bot Signals

- Known bad bots: Identified using an external list of bad user agents.
- Fake Google bots: User agent contains `Googlebot`, but the IP address does not belong to Google.
- Libraries and net tools: User agent strings like `curl`, `python-requests`, `PostmanRuntime`.
- Path traversal attacks: URLs containing `"/../"`

### Human Traffic Signals

- Negative of bot signals
- User agent strings that do not match known bad bots, libraries, and net tools
- URLs that do not contain path traversal patterns

## License

This project is licensed under the MIT License.
