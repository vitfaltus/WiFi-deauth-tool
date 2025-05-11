# WiFi-deauth-tool
This project serves as a proof of concept. As the name suggests, the program is designed to disconnect clients from a wireless access point by exploiting the lack of verification during the deauthentication process.

## Modes

The program offers several operational modes:

- **DDOS Mode**: In this mode, your device's network card sends deauthentication frames to a specified access point using a broadcast address.
- **DOS Mode**: This mode allows you to target a specific MAC address.
- **Priority Deauthentication Mode**: This mode attempts to disconnect all clients except one, ideally your own device.

## Limitations

While this tool can be useful for testing your network for example, it has several major limitations:

- **Security Protocols**: The deauthentication method works primarily on networks secured with WPA2 or weaker protocols like WEP. Some WPA2 networks may also be vulnerable if they lack optional protections against such attacks. However, WPA3 networks are immune to this method as they enforce protection against deauthentication attacks.

- **Frequency Band**: The program operates only on the 2.4 GHz network band because the underlying library, Scapy, does not support 5 GHz networks.

- **System Compatibility**: The program uses commands like `ifconfig`, `iwconfig`, and `systemctl`, and it accesses the `/sys/class/net` directory for network interfaces. While it has been developed and tested on Ubuntu, compatibility with other distributions is not guaranteed.

## Usage

1. **Run with Admin Privileges**: Launch the program with administrative privileges. Right after launch, it will display all detected network interfaces.

2. **Select Interface**: Copy and paste the name of the desired network interface.

3. **Help Menu**: Upon successful interface selection, the program will display a help menu with all available commands and their descriptions.

4. **Recommended Workflow**:
   - Set the action time using the `set time` command (in seconds).
   - Use the `set interface` command to change the selected network interface (if you want to change it).
   - Scan for visible networks to gather information using `scan` command.
   - Use the `set gateway` command to set the gateway target mac address.
   - Use the `clients` command to scan for clients on a specific network.
   - Use the deauth modes listed in the help menu.

## Thoughts

I've written this program to learn more about Wi-Fi security (and to graduate from high school). It is not intended for malicious use. In a few years, it will be obsolete (as it partially is now), since most new devices come with WPA3 and 5G, so your success rate won't be high. However it is useful to check if your wireless network is vulnerable to this type of attack (or disconnecting everyone else from your network since your video won't load).