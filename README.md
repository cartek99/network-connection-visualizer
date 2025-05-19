# Network Connection Visualizer

Visualize your computer’s active public network connections on a modern world map.

## Features

- Lists all external network connections by process, PID, remote IP, organization, and location.
- Plots connections on a world map using the latest Stadia Maps basemap.
- Logs all results to a file with timestamps.
- Table view in the console for quick inspection.

## Requirements

- Python 3.8+
- pip

- **macOS:**
Need to run as "sudo ."

## Installation

1. **Clone this repo:**

    ```
    git clone https://github.com/cartek99/network-connection-visualizer.git
    cd network-connection-visualizer
    ```

2. **Install dependencies:**

    - **macOS:**
        ```
        brew install geos proj
        pip install --upgrade pip setuptools wheel
        pip install -r requirements.txt
        ```
    - **Linux (Debian/Ubuntu):**
        ```
        sudo apt-get install libgeos-dev libproj-dev
        pip install --upgrade pip setuptools wheel
        pip install -r requirements.txt
        ```
    - **Windows:**
        ```
        pip install --upgrade pip setuptools wheel
        pip install -r requirements.txt
        ```

    - **Or use Conda (recommended for all platforms):**
        ```
        conda env create -f environment.yml
        conda activate netviz
        ```

## Usage

```bash
python main.py

**macOS:**
sudo python main.py
 
