# Network Connection Visualizer

Visualize your computer’s active public network connections on a world map.

## Features

- Detects all active public (non-local) network connections.
- Uses geolocation to plot remote hosts on a world map.
- Generates a high-quality image showing your global network footprint.

## Requirements

- Python 3.8+
- pip

## Installation

1. Clone this repo:

    ```
    git clone https://github.com/YOUR_GITHUB_USERNAME/network-connection-visualizer.git
    cd network-connection-visualizer
    ```

2. Install dependencies:

    ```
    pip install -r requirements.txt
    ```

## Usage

1. Edit `main.py` if you want to change your source location (default is Singapore).
2. Run:

    ```
    python main.py
    ```

3. A PNG map of your current network connections will be created and displayed.

## Notes

- By default, private/local network connections are filtered out.
- For Windows, if you see warnings about scripts not on PATH, see the [Python documentation](https://docs.python.org/3/using/windows.html#excursus-setting-environment-variables).

## License

MIT License
