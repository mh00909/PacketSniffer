# Packet Sniffer

A simple packet sniffer application built using C and GTK+3, designed to capture and display network packets along with their detailed statistics.

## Features

- Capture network packets in real-time.
- Display detailed information about each packet, including headers and payload.
- Filter packets based on protocol types (TCP, UDP, ICMP, etc.).
- Display statistics for different types of captured packets.

## Requirements

- GTK+3
- libpcap

## Installation

### Prerequisites

Ensure that you have `GTK+3` and `libpcap` installed on your system. You can install them using your package manager.

For Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install libgtk-3-dev libpcap-dev
```
For Fedora:

```sh
sudo dnf install gtk3-devel libpcap-devel
```
For Arch Linux:
```sh
sudo pacman -S gtk3 libpcap
```

### Clone the Repository
```
git clone https://github.com/mh00909/PacketSniffer.git
```
### Build
```
gcc main.c packet_handler.c gui.c -o packet_sniffer `pkg-config --cflags --libs gtk+-3.0` -lpcap
```
## Usage
Run the application with superuser privileges to capture packets:
```
sudo ./packet_sniffer
```
### Interface
- Interface: Enter the network interface you want to capture packets from.
- Filter Type: Select the type of filter to apply (e.g., tcp, udp, icmp).
- Filter Value: Enter the value for the selected filter type if required (e.g., a specific port number).
- Start/Stop: Buttons to start or stop packet capturing.
- Details: Displays detailed information about the selected packet.
- Statistics: Shows the count of captured packets by type.
