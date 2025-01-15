# 📡Network Traffic Analyzer

Welcome to the **Network Traffic Analyzer** tool! 🛠️ This tool helps you capture and analyze network traffic in real-time, providing insights into packet flows, protocols, and more. 📊

## Features ✨
- **Capture Traffic**: Monitor traffic from your selected network interface 🌐
- **Analyze Packets**: View detailed information about each packet 💥
- **Protocol Monitoring**: Track TCP, UDP, ICMP, and other protocols 📡
- **Save Packets**: Store captured traffic in `.pcap` format for later analysis 💾

## Installation 🔧

1. Clone this repository:
```bash
   git clone https://github.com/bandwidthlow/NetPulse.git
```
   
2.Install dependencies:
```bash
pip install -r requirements.txt
```

3.Set executable permissions for the script:
```bash
chmod +x main.py.py
```

4.Run the tool:
```bash
sudo ./main.py
```

## Usage 📈
- Run the tool and choose the network interface to start capturing traffic.
- Filter by protocol (TCP, UDP, ICMP, etc.) or leave it empty for all traffic.
- Save the captured packets to a `.pcap` file for future analysis.

## License 📜
Distributed under the MIT License. See [LICENSE](LICENSE) for more information.
