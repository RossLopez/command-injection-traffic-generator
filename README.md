# Synthetic Web Traffic Generator

This Python script generates synthetic web traffic data, including both benign and command injection traffic. The generated data is saved in a CSV file named `synthetic_web_traffic.csv`.

## Features

The script includes functions to generate:

- Random 384-bit Pre-Shared Key
- Random IPV4 and IPV6 IP Addresses
- Random Port
- Random application engine file and extension
- Random timestamp that is a day in the past
- Random query parameter to be used with the generated file extension
- Random benign traffic
- Random command injection traffic

## Usage

To use this script, simply run it with a Python interpreter. The script does not require any command-line arguments.

```bash
python synthetic_web_traffic_generator.py
```

## Output

The script generates a CSV file named `synthetic_web_traffic.csv` with the following fields:

- `timestamp`: The timestamp of the web request.
- `url`: The URL of the web request.
- `method`: The HTTP method of the web request (GET, POST, PUT, DELETE).
- `query`: The query parameters of the web request.
- `label`: The label indicating whether the web request is benign (0) or a command injection attack (1).

## Dependencies

The script requires the following Python libraries:

- `random`
- `csv`
- `ipaddress`
- `secrets`
- `base64`
- `string`
- `datetime`

## Note

This script is intended for generating synthetic data for testing and development purposes. It should not be used for malicious purposes.