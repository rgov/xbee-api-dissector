local proto         = Proto("xbee", "XBee API")
proto.fields.data   = ProtoField.bytes("xbee.data", "Command Data")

local command_names = {
    [0x08] = "AT Command",
    [0x09] = "AT Command - Queue Parameter Value",
    [0x10] = "Zigbee Transmit Request",
    [0x11] = "Explicit Addressing Command Request",
    [0x17] = "Remote Command Request",
    [0x21] = "Create Source Route",
    [0x88] = "AT Command Response",
    [0x8A] = "Modem Status",
    [0x8B] = "Zigbee Transmit Status",
    [0x90] = "Zigbee Receive Packet",
    [0x91] = "Explicit Receive Indicator",
    [0x92] = "Zigbee I/O Data Sample Rx Indicator",
    [0x94] = "XBee Sensor Read Indicator",
    [0x95] = "Node Identification Indicator",
    [0x97] = "Remote Command Response",
    [0x98] = "Extended Modem Status",
    [0xA0] = "Over-the-Air Firmware Update Status",
    [0xA1] = "Route Record Indicator",
    [0xA3] = "Many-to-One Route Request Indicator"
}
proto.fields.cmdid                    = ProtoField.uint8("xbee.cmdid", "Command ID", base.HEX, command_names)

-- Fields for Zigbee Transmit Request (0x10)
proto.fields["0x10.frame_id"]         = ProtoField.uint8("xbee.0x10.frame_id", "Frame ID", base.HEX)
proto.fields["0x10.dest_addr64"]      = ProtoField.uint64("xbee.0x10.dest_addr64", "64-bit Destination Address", base
    .HEX)
proto.fields["0x10.dest_addr16"]      = ProtoField.uint16("xbee.0x10.dest_addr16", "16-bit Destination Address", base
    .HEX)
proto.fields["0x10.broadcast_radius"] = ProtoField.uint8("xbee.0x10.broadcast_radius", "Broadcast Radius", base.DEC)
proto.fields["0x10.tx_options"]       = ProtoField.uint8("xbee.0x10.tx_options", "Transmit Options", base.HEX)
proto.fields["0x10.rf_data"]          = ProtoField.bytes("xbee.0x10.rf_data", "RF Data")

-- Fields for Zigbee Receive Packet (0x90)
proto.fields["0x90.src_addr64"]       = ProtoField.uint64("xbee.0x90.src_addr64", "64-bit Source Address", base.HEX)
proto.fields["0x90.src_addr16"]       = ProtoField.uint16("xbee.0x90.src_addr16", "16-bit Source Address", base.HEX)
proto.fields["0x90.rx_options"]       = ProtoField.uint8("xbee.0x90.rx_options", "Receive Options", base.HEX)
proto.fields["0x90.rf_data"]          = ProtoField.bytes("xbee.0x90.rf_data", "RF Data")


-- In the AP=2 mode, the wire format includes escape characters. This function
-- unescapes a ByteArray and returns a new one.
local function unescape(buf)
    local out = ByteArray.new()
    out:set_size(buf:len())

    local i = 0
    local j = 0
    while i < buf:len() do
        local b = buf:uint(i, 1)
        if b == 0x7D then
            if i + 1 >= buf:len() then return nil end -- out of bounds
            out:set_index(j, bit.bxor(buf:uint(i + 1, 1), 0x20))
            i = i + 2
        else
            out:set_index(j, b)
            i = i + 1
        end
        j = j + 1
    end

    out:set_size(j)
    return out
end

-- Validate the checksum of a ByteArray. Also returns false if the length
-- exceeds the buffer size.
local function validate_checksum(buf)
    if buf:len() < 4 then return false end
    local data_len = buf:uint(1, 2)
    if buf:len() < (1 + 2 + data_len + 1) then return false end
    local sum = 0
    for i = 3, 2 + data_len do
        sum = (sum + buf:uint(i, 1)) % 256
    end
    return ((0xFF - sum) % 256) == buf:uint(3 + data_len, 1)
end


-- Parse Zigbee Transmit Request (0x10)
local function parse_tx_request(tvb, tree)
    tree:add(proto.fields["0x10.frame_id"], tvb:range(0, 1))
    tree:add(proto.fields["0x10.dest_addr64"], tvb:range(1, 8))
    tree:add(proto.fields["0x10.dest_addr16"], tvb:range(9, 2))
    tree:add(proto.fields["0x10.broadcast_radius"], tvb:range(11, 1))
    tree:add(proto.fields["0x10.tx_options"], tvb:range(12, 1))
    if tvb:len() > 13 then
        tree:add(proto.fields["0x10.rf_data"], tvb:range(13, tvb:len() - 13))
    end
end

-- Parse Zigbee Receive Packet (0x90)
local function parse_rx_packet(tvb, tree)
    tree:add(proto.fields["0x90.src_addr64"], tvb:range(0, 8))
    tree:add(proto.fields["0x90.src_addr16"], tvb:range(8, 2))
    tree:add(proto.fields["0x90.rx_options"], tvb:range(10, 1))
    if tvb:len() > 11 then
        tree:add(proto.fields["0x90.rf_data"], tvb:range(11, tvb:len() - 11))
    end
end


local function read_raw_pdu(buffer, tvb, tree)
    -- Determine how long the complete PDU ought to be. If we don't have enough
    -- data, return nil so this is marked as an incomplete fragment.
    if buffer:len() < 4 then return nil end
    local data_len = buffer:uint(1, 2)
    local total_len = 1 + 2 + data_len + 1
    if buffer:len() < total_len then
        return nil
    end

    -- Our Tvb might be nil if we are parsing a reassembled buffer, or non-nil
    -- if we are parsing a PDU from within the current packet or an unescaped
    -- buffer created by read_escaped_pdu().
    if not tvb then
        tvb = buffer:tvb("XBee API Frame (reasm)")
    end

    local cmdid = tvb:range(3, 1):uint()
    local cmdname = command_names[cmdid]

    tree:add(proto.fields.cmdid, tvb:range(3, 1))
    local subtree = tree:add(cmdname)

    if cmdid == 0x10 then
        parse_tx_request(tvb:range(4, data_len), subtree)
    elseif cmdid == 0x90 then
        parse_rx_packet(tvb:range(4, data_len), subtree)
    end

    return total_len, cmdname or "Unknown Command"
end


-- Unescapes the given buffer, which is assumed to be in escaped format.
local function read_escaped_pdu(buffer, tvb, tree)
    local unesc = unescape(buffer)
    if not unesc or unesc:len() == buffer:len() or not validate_checksum(unesc)
    then
        return nil
    end

    -- At this point we have a valid, unescaped PDU, so it's OK to make a new
    -- Tvb that will pop up in the UI.
    local newtvb = unesc:tvb("XBee API Frame (" ..
        ((not tvb) and "reasm, " or "") .. "unesc)")
    return read_raw_pdu(unesc, newtvb, tree)
end


-- Reads a complete PDU. Since we don't know whether the PDU is in the escaped
-- (AP=2) format or not, we first try to unescape it, and if the checksum isn't
-- valid, we try to read it as a raw PDU.
--
-- buffer is the ByteArray containing the data to parse.
--
-- tvb is either a Tvb for the current packet, or nil if the PDU begain in an
-- earlier packet. In this case, create a new Tvb from the buffer *after* we
-- have validated that we have a complete PDU.
--
-- Returns the number of bytes consumed, or nil if there is not a complete PDU
-- in the buffer. Optionally, also return  a string to be appended to the
-- packet's Info column.
local function read_complete_pdu(buffer, tvb, tree)
    local consumed, info = read_escaped_pdu(buffer, tvb, tree)
    if consumed then
        return consumed, info
    end
    return read_raw_pdu(buffer, tvb, tree)
end


--------------------------------------------------------------------------------
--  REASSEMBLY  --  based on https://github.com/rgov/wireshark-udp-reassembly
--------------------------------------------------------------------------------

-- The reassembly table is a table of tables,
--
--   fragments_by_stream[stream_key][packet_number] = {
--     buffer = <string or nil>,
--     prev = <number or nil>
--   }
--
-- stream_key is a unique identifier for each unidirectional stream, generated
-- by get_stream_key().
--
-- buffer is the unprocessed fragment within the given packet. If there were no
-- incomplete PDUs, then buffer is nil. Note this is distinct from an empty
-- buffer, which means that there was an incomplete PDU, but the packet did not
-- contribute any data.
--
-- prev is the packet number of the previous packet that contains a fragment of
-- the same PDU. This will be nil if this is the first fragment of a PDU.
local fragments_by_stream = {}


-- Returns a unique identifier for the stream that the packet belongs to.
local function get_stream_key(pinfo)
    return tostring(pinfo.src) .. ":" .. tostring(pinfo.src_port) ..
        "->" .. tostring(pinfo.dst) .. ":" .. tostring(pinfo.dst_port)
end


function proto.dissector(tvb, pinfo, tree)
    -- Look up the reassembly state for this stream
    local key = get_stream_key(pinfo)
    if not fragments_by_stream[key] then
        fragments_by_stream[key] = {}
    end
    local fragments = fragments_by_stream[key]

    -- Find the previous packet in this stream, i.e., the one with the greatest
    -- packet number less than the current packet number.
    local prev_pkt_num = nil
    for pkt_num, state in pairs(fragments) do
        if pkt_num < pinfo.number then
            if (not prev_pkt_num) or (pkt_num > prev_pkt_num) then
                prev_pkt_num = pkt_num
            end
        end
    end

    -- If the previous packet has a nil buffer, then it was not part of an
    -- incomplete PDU (distinct from an empty buffer).
    if prev_pkt_num and not fragments[prev_pkt_num].buffer then
        prev_pkt_num = nil
    end

    -- Otherwise, follow the linked list backwards to assemble all the fragments
    -- of the incomplete PDU.
    local whole_buffer = ByteArray.new()
    local i = prev_pkt_num
    while i do
        local prev_state = fragments[i]
        if prev_state.buffer then
            whole_buffer:prepend(ByteArray.new(prev_state.buffer, true))
        end
        i = prev_state.prev
    end

    local earlier_fragment_len = whole_buffer:len()
    local was_reassembled = earlier_fragment_len > 0

    -- Add the current packet data, too.
    whole_buffer:append(tvb:bytes())

    -- Loop to extract one or more complete PDUs.
    local offset = 0
    local pdu_count = 0
    local infos = {}
    while offset < whole_buffer:len() do
        -- If we are parsing from within the current packet, then we will pass
        -- read_complete_pdu() a TvbRange within the current packet. Otherwise,
        -- we pass nil, indicating that we are parsing from a reassembled
        -- buffer, and a new Tvb should be created if a complete PDU is found.
        local tvb2 = nil
        if offset >= earlier_fragment_len then
            tvb2 = tvb:range(offset - earlier_fragment_len)
        end

        -- Try to consume a complete PDU from the buffer at offset. If this
        -- returns nil, then it is an incomplete PDU.
        local consumed, info = read_complete_pdu(
            whole_buffer:subset(offset, whole_buffer:len() - offset),
            tvb2,
            tree
        )

        if not consumed then
            table.insert(infos, "fragment")
            break
        end

        table.insert(infos, info)
        offset = offset + consumed
        pdu_count = pdu_count + 1
    end

    -- Set the Info column to the comma-delimited list of info strings.
    pinfo.cols.info = table.concat(infos, ", ")
    pinfo.cols.protocol = proto.description

    -- If there is any left over data, we will save the unconsumed fragment in
    -- the fragments table.
    local leftover = nil
    if offset < whole_buffer:len() then
        local consumed_from_current = math.max(0, offset - earlier_fragment_len)
        leftover = tvb:range(consumed_from_current):bytes():raw()
    end

    -- If we failed to extract a full PDU, then use the linked list to connect
    -- our incomplete buffer with the previous packet.
    if pdu_count == 0 then
        fragments[pinfo.number] = { buffer = leftover, prev = prev_pkt_num }
    else
        fragments[pinfo.number] = { buffer = leftover, prev = nil }
    end
end

--------------------------------------------------------------------------------

-- Register the dissector for a given UDP port
local udp_port = DissectorTable.get("udp.port")
udp_port:add(11243, proto.dissector)
