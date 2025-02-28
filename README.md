# XBee API Dissector for Wireshark

This repository contains a *very basic* Wireshark dissector for Xbee API communication between a host device and an XBee Zigbee RF Module.

The dissector is partially generated from [the specification](https://www.digi.com/resources/documentation/DigiDocs/90002002/Default.htm#Containers/cont_xbee_pro_zigbee_api_operation.htm).

Only Zigbee Transmit Request and Zigbee Receive Packet frames are dissected.

To capture serial traffic, refer to the [rgov/serial2pcap](https://github.com/rgov/serial2pcap) repository.

To install the dissector, copy the `xbee.lua` script into the Wireshark plugins directory. The location of the plugins directory can be found by opening Wireshark and navigating to About Wireshark → Folders. Load the plugin using Analyze → Reload Lua Plugins.
