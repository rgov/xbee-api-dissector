-- XBee API Protocol dissector for Wireshark
local xbee_proto       = Proto("xbee", "XBee API Protocol")

-- Main header fields
local f_start          = ProtoField.uint8("xbee.start", "Start Delimiter", base.HEX)
local f_length         = ProtoField.uint16("xbee.length", "Length", base.DEC)
local f_escaped        = ProtoField.bool("xbee.escaped", "Escaped", 8, nil, 0xFF)
local f_frame_data     = ProtoField.bytes("xbee.data", "Frame Data")
local f_checksum       = ProtoField.uint8("xbee.checksum", "Checksum", base.HEX)
local f_valid_checksum = ProtoField.bool("xbee.checksum_valid", "Checksum Valid", 8, nil, 0xFF)
local f_cmdid          = ProtoField.uint8("xbee.cmdid", "API Identifier", base.HEX)
local f_raw_data       = ProtoField.bytes("xbee.raw", "Raw Frame Data")

-- Fields for Transmit Request (0x10)
local f_tx_frameid     = ProtoField.uint8("xbee.10.frameid", "Frame ID", base.HEX)
local f_tx_dest64      = ProtoField.uint64("xbee.10.dest64", "64-bit Destination", base.HEX)
local f_tx_dest16      = ProtoField.uint16("xbee.10.dest16", "16-bit Destination", base.HEX)
local f_tx_radius      = ProtoField.uint8("xbee.10.radius", "Broadcast Radius", base.DEC)
local f_tx_options     = ProtoField.uint8("xbee.10.options", "Transmit Options", base.HEX)
local f_tx_data        = ProtoField.bytes("xbee.10.data", "RF Data")

-- Fields for Explicit Addressing Command Request (0x11)
local f_ex_frameid     = ProtoField.uint8("xbee.11.frameid", "Frame ID", base.HEX)
local f_ex_dest64      = ProtoField.uint64("xbee.11.dest64", "64-bit Destination", base.HEX)
local f_ex_dest16      = ProtoField.uint16("xbee.11.dest16", "16-bit Destination", base.HEX)
local f_ex_src_ep      = ProtoField.uint8("xbee.11.src_ep", "Source Endpoint", base.HEX)
local f_ex_dest_ep     = ProtoField.uint8("xbee.11.dest_ep", "Destination Endpoint", base.HEX)
local f_ex_cluster     = ProtoField.uint16("xbee.11.cluster", "Cluster ID", base.HEX)
local f_ex_profile     = ProtoField.uint16("xbee.11.profile", "Profile ID", base.HEX)
local f_ex_radius      = ProtoField.uint8("xbee.11.radius", "Broadcast Radius", base.DEC)
local f_ex_options     = ProtoField.uint8("xbee.11.options", "Transmit Options", base.HEX)
local f_ex_data        = ProtoField.bytes("xbee.11.data", "Command Data")

-- Fields for Zigbee Receive Packet (0x90)
local f_rx_source64    = ProtoField.uint64("xbee.90.src64", "64-bit Source", base.HEX)
local f_rx_source16    = ProtoField.uint16("xbee.90.src16", "16-bit Source", base.HEX)
local f_rx_options     = ProtoField.uint8("xbee.90.options", "Receive Options", base.HEX)
local f_rx_data        = ProtoField.bytes("xbee.90.data", "RF Data")

-- Fields for Explicit Receive Indicator (0x91)
local f_er_src64       = ProtoField.uint64("xbee.91.src64", "64-bit Source", base.HEX)
local f_er_src16       = ProtoField.uint16("xbee.91.src16", "16-bit Source", base.HEX)
local f_er_src_ep      = ProtoField.uint8("xbee.91.src_ep", "Source Endpoint", base.HEX)
local f_er_dest_ep     = ProtoField.uint8("xbee.91.dest_ep", "Destination Endpoint", base.HEX)
local f_er_cluster     = ProtoField.uint16("xbee.91.cluster", "Cluster ID", base.HEX)
local f_er_profile     = ProtoField.uint16("xbee.91.profile", "Profile ID", base.HEX)
local f_er_options     = ProtoField.uint8("xbee.91.options", "Receive Options", base.HEX)
local f_er_data        = ProtoField.bytes("xbee.91.data", "RF Data")

xbee_proto.fields      = {
    f_start, f_length, f_escaped, f_frame_data, f_checksum, f_valid_checksum, f_cmdid, f_raw_data,
    f_tx_frameid, f_tx_dest64, f_tx_dest16, f_tx_radius, f_tx_options, f_tx_data,
    f_ex_frameid, f_ex_dest64, f_ex_dest16, f_ex_src_ep, f_ex_dest_ep, f_ex_cluster, f_ex_profile, f_ex_radius,
    f_ex_options, f_ex_data,
    f_rx_source64, f_rx_source16, f_rx_options, f_rx_data,
    f_er_src64, f_er_src_ep, f_er_src16, f_er_dest_ep, f_er_cluster, f_er_profile, f_er_options, f_er_data
}

-- Unescape function:
-- Processes a TVB range containing escaped bytes. An escape is signaled by 0x7D; the following byte
-- is XOR'd with 0x20. Returns a new ByteArray with the unescaped data.
local function unescape_tvb(tvb_range)
    local ba = ByteArray.new()
    local len = tvb_range:len()
    local i = 0
    while i < len do
        local byte = tvb_range:range(i, 1):uint()
        if byte == 0x7D then
            if i + 1 < len then
                local next_byte = tvb_range:range(i + 1, 1):uint()
                ba:append_uint8(bit32.bxor(next_byte, 0x20))
                i = i + 2
            else
                ba:append_uint8(byte)
                i = i + 1
            end
        else
            ba:append_uint8(byte)
            i = i + 1
        end
    end
    return ba
end

-- Parse Transmit Request (0x10)
local function parse_tx_request(frame_data, tree)
    local st = tree:add(xbee_proto, frame_data, "Zigbee Transmit Request (0x10)")
    if frame_data:len() < 14 then
        st:add_expert_info(PI_MALFORMED, PI_ERROR, "Frame too short for 0x10")
        return
    end
    local ofs = 0
    st:add(f_cmdid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_tx_frameid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_tx_dest64, frame_data:range(ofs, 8))
    ofs = ofs + 8
    st:add(f_tx_dest16, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_tx_radius, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_tx_options, frame_data:range(ofs, 1))
    ofs = ofs + 1
    if ofs < frame_data:len() then
        st:add(f_tx_data, frame_data:range(ofs, frame_data:len() - ofs))
    end
end

-- Parse Explicit Addressing Command Request (0x11)
local function parse_explicit_addressing(frame_data, tree)
    local st = tree:add(xbee_proto, frame_data, "Explicit Addressing Command Request (0x11)")
    if frame_data:len() < 20 then
        st:add_expert_info(PI_MALFORMED, PI_ERROR, "Frame too short for 0x11")
        return
    end
    local ofs = 0
    st:add(f_cmdid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_ex_frameid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_ex_dest64, frame_data:range(ofs, 8))
    ofs = ofs + 8
    st:add(f_ex_dest16, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_ex_src_ep, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_ex_dest_ep, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_ex_cluster, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_ex_profile, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_ex_radius, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_ex_options, frame_data:range(ofs, 1))
    ofs = ofs + 1
    if ofs < frame_data:len() then
        st:add(f_ex_data, frame_data:range(ofs, frame_data:len() - ofs))
    end
end

-- Parse Zigbee Receive Packet (0x90)
local function parse_rx_packet(frame_data, tree)
    local st = tree:add(xbee_proto, frame_data, "Zigbee Receive Packet (0x90)")
    if frame_data:len() < 12 then
        st:add_expert_info(PI_MALFORMED, PI_ERROR, "Frame too short for 0x90")
        return
    end
    local ofs = 0
    st:add(f_cmdid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_rx_source64, frame_data:range(ofs, 8))
    ofs = ofs + 8
    st:add(f_rx_source16, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_rx_options, frame_data:range(ofs, 1))
    ofs = ofs + 1
    if ofs < frame_data:len() then
        st:add(f_rx_data, frame_data:range(ofs, frame_data:len() - ofs))
    end
end

-- Parse Explicit Receive Indicator (0x91)
local function parse_explicit_receive(frame_data, tree)
    local st = tree:add(xbee_proto, frame_data, "Explicit Receive Indicator (0x91)")
    if frame_data:len() < 18 then
        st:add_expert_info(PI_MALFORMED, PI_ERROR, "Frame too short for 0x91")
        return
    end
    local ofs = 0
    st:add(f_cmdid, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_er_src64, frame_data:range(ofs, 8))
    ofs = ofs + 8
    st:add(f_er_src16, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_er_src_ep, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_er_dest_ep, frame_data:range(ofs, 1))
    ofs = ofs + 1
    st:add(f_er_cluster, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_er_profile, frame_data:range(ofs, 2))
    ofs = ofs + 2
    st:add(f_er_options, frame_data:range(ofs, 1))
    ofs = ofs + 1
    if ofs < frame_data:len() then
        st:add(f_er_data, frame_data:range(ofs, frame_data:len() - ofs))
    end
end

function xbee_proto.dissector(tvb, pinfo, tree)
    if tvb:len() < 4 then return end
    if tvb(0, 1):uint() ~= 0x7E then return end

    pinfo.cols.protocol = "XBee"
    local offset = 0

    local start_delim = tvb(offset, 1)
    offset = offset + 1
    local len_field = tvb(offset, 2)
    local frame_length = len_field:uint()
    offset = offset + 2
    local total_len = frame_length + 1
    if tvb:len() < 3 + total_len then return end

    local tree_root = tree:add(xbee_proto, tvb(), "XBee API Protocol")
    tree_root:add(f_start, start_delim)
    tree_root:add(f_length, len_field)

    -- Retrieve the raw frame bytes (may include escape sequences)
    local raw_frame = tvb:range(offset, total_len)

    -- Efficiently check for the escape character (0x7D) using string.find.
    local raw_str = raw_frame:bytes():raw()
    local has_escape = string.find(raw_str, "\x7D", 1, true) ~= nil

    -- If escape characters are detected, attempt to unescape the frame.
    -- Verify the checksum on the unescaped frame; if valid, use the unescaped data.
    local used_escape = false
    local data_tvb = raw_frame
    if has_escape then
        local unesc_ba = unescape_tvb(raw_frame)
        local unesc_tvb = unesc_ba:tvb("Unescaped XBee Frame")
        if unesc_tvb:len() >= 1 then
            local unesc_chk = unesc_tvb:range(unesc_tvb:len() - 1, 1):uint()
            local sum = 0
            for j = 0, unesc_tvb:len() - 2 do
                sum = (sum + unesc_tvb:range(j, 1):uint()) % 256
            end
            if (0xFF - sum) % 256 == unesc_chk then
                data_tvb = unesc_tvb
                used_escape = true
            end
        end
    end
    tree_root:add(f_escaped, used_escape)

    local frame_data_len = data_tvb:len() - 1
    local frame_data = data_tvb:range(0, frame_data_len)
    local recv_checksum = data_tvb:range(frame_data_len, 1):uint()
    tree_root:add(f_frame_data, raw_frame)
    tree_root:add(f_checksum, data_tvb:range(frame_data_len, 1))

    local sum = 0
    for i = 0, frame_data:len() - 1 do
        sum = (sum + frame_data:range(i, 1):uint()) % 256
    end
    local calc_checksum = (0xFF - sum) % 256
    tree_root:add(f_valid_checksum, calc_checksum == recv_checksum)

    if frame_data:len() < 1 then return end
    local api_id = frame_data:range(0, 1):uint()
    tree_root:add(f_cmdid, frame_data:range(0, 1))

    if api_id == 0x10 then
        parse_tx_request(frame_data, tree_root)
    elseif api_id == 0x11 then
        parse_explicit_addressing(frame_data, tree_root)
    elseif api_id == 0x90 then
        parse_rx_packet(frame_data, tree_root)
    elseif api_id == 0x91 then
        parse_explicit_receive(frame_data, tree_root)
    else
        tree_root:add(f_raw_data, frame_data)
    end
end

-- Hack: Register the dissector for Ethernet packets with EtherType 0x4141
local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x4141, xbee_proto)
