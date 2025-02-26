# XBee API Dissector for Wireshark

This repository contains two scripts:

1. A basic Wireshark dissector for Xbee API frames generated from the [specification](https://www.digi.com/resources/documentation/DigiDocs/90002002/Default.htm#Containers/cont_xbee_pro_zigbee_api_operation.htm).

    Only Zigbee Transmit Request and Zigbee Receive Packet frames are dissected.

    The dissector recognizes escaped frames and should dissect them correctly. However, fragmented frames are not currently reassembled.

    Copy the `xbee.lua` script into the Wireshark plugins directory. The location of the plugins directory can be found by opening Wireshark and navigating to About Wireshark → Folders. Load the plugin using Analyze → Reload Lua Plugins.

2. A Python script for generating a PCAP file from a capture of [Serial Port Monitor](https://www.serial-port-monitor.org/) by Electonic Team, Inc.

    The script cannot understand the proprietary .spm file format, so the user must export the capture to a CSV file by right clicking and selecting Export to...

The conversion process synthesizes Ethernet frames for each serial read and write operation. The Ethernet frame uses 00:00:00:00:00 as the MAC address of the host and the device MAC address is based on the serial port number. The EtherType is set to the bogus value 0x4141.
