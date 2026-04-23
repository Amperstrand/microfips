-- FIPS FMP dissector for Wireshark/tshark (UDP/2121 and BLE L2CAP).
--
-- Handles FMP frames carried over:
--   1. UDP port 2121 (raw FMP frames)
--   2. BLE L2CAP CoC with PSM 0x0085 (2-byte BE length-prefixed FMP frames)
--
-- UDP usage:
--   tshark -X lua_script:tools/fips_dissector.lua -f "udp port 2121"
--   wireshark -X lua_script:tools/fips_dissector.lua
--
-- BLE L2CAP usage (btmon capture opened in Wireshark):
--   wireshark -X lua_script:tools/fips_dissector.lua capture.btsnoop
--   tshark -r capture.btsnoop -X lua_script:tools/fips_dissector.lua -V
--
-- Decrypted BLE capture (from fips-decrypt --output):
--   wireshark -X lua_script:tools/fips_dissector.lua decrypted.pcap
--   tshark -r decrypted.pcap -X lua_script:tools/fips_dissector.lua -Y 'fips.phase == 0'
--
-- Wireshark preferences (Edit -> Preferences -> Protocols -> FIPS):
--   UDP port:        default 2121
--   BLE L2CAP PSM:   default 0x0085 (133 decimal)
--   Transport mode:  0 = Auto-detect (default), 1 = UDP, 2 = BLE L2CAP

local p_fips = Proto("fips", "FIPS FMP")

---------------------------------------------------------------------------
-- Protocol fields
---------------------------------------------------------------------------
local f_version = ProtoField.uint8("fips.version", "Version", base.HEX)
local f_phase = ProtoField.uint8("fips.phase", "Phase", base.HEX)
local f_flags = ProtoField.uint8("fips.flags", "Flags", base.HEX)
local f_payload_length = ProtoField.uint16("fips.payload_length", "Payload Length", base.DEC)
local f_sender_idx = ProtoField.uint32("fips.sender_idx", "Sender Index", base.HEX)
local f_receiver_idx = ProtoField.uint32("fips.receiver_idx", "Receiver Index", base.HEX)
local f_counter = ProtoField.uint64("fips.counter", "Counter", base.DEC)
local f_noise_payload = ProtoField.bytes("fips.noise_payload", "Encrypted Payload")

-- BLE-specific fields
local f_ble_length = ProtoField.uint16("fips.ble_length_prefix", "BLE L2CAP Length Prefix", base.DEC)
local f_transport = ProtoField.string("fips.transport", "Transport")

p_fips.fields = {
    f_version,
    f_phase,
    f_flags,
    f_payload_length,
    f_sender_idx,
    f_receiver_idx,
    f_counter,
    f_noise_payload,
    f_ble_length,
    f_transport,
}

---------------------------------------------------------------------------
-- Constants
---------------------------------------------------------------------------
local PHASE_ESTABLISHED = 0x00
local PHASE_MSG1 = 0x01
local PHASE_MSG2 = 0x02

local PREFIX_SIZE = 4   -- version+phase(1) + flags(1) + payload_length(2)
local IDX_SIZE = 4
local COUNTER_SIZE = 8
local BLE_PREFIX_SIZE = 2

local TRANSPORT_AUTO = 0
local TRANSPORT_UDP = 1
local TRANSPORT_BLE = 2

---------------------------------------------------------------------------
-- Preferences
---------------------------------------------------------------------------
p_fips.prefs.udp_port = Pref.uint("UDP port", 2121, "UDP port for FMP frames (0 to disable)")
p_fips.prefs.ble_psm = Pref.uint("BLE L2CAP PSM", 0x0085, "L2CAP PSM for FMP frames (0 to disable)")
p_fips.prefs.transport_mode = Pref.uint(
    "Transport mode",
    TRANSPORT_AUTO,
    "How frames are encapsulated: 0=Auto-detect, 1=UDP (no prefix), 2=BLE L2CAP (2-byte BE length prefix)"
)

---------------------------------------------------------------------------
-- Helpers
---------------------------------------------------------------------------
local function phase_name(phase)
    if phase == PHASE_MSG1 then
        return "MSG1"
    elseif phase == PHASE_MSG2 then
        return "MSG2"
    elseif phase == PHASE_ESTABLISHED then
        return "ESTABLISHED"
    end
    return "UNKNOWN"
end

---------------------------------------------------------------------------
-- Core FMP dissector
--
-- Parses an FMP frame from *buffer* (no BLE length prefix) and adds fields
-- to *subtree*.  *transport_name* is a human-readable label ("UDP" or
-- "BLE L2CAP") added via the fips.transport field.
-- Returns the number of bytes consumed, or 0 on error.
---------------------------------------------------------------------------
local function dissect_fmp(buffer, pinfo, subtree, transport_name)
    local packet_len = buffer:len()
    if packet_len < PREFIX_SIZE then
        pinfo.cols.protocol = "FIPS"
        pinfo.cols.info:set("FIPS Malformed (short prefix)")
        return 0
    end

    pinfo.cols.protocol = "FIPS"

    -- Add transport field (generated, highlights nothing in the byte pane)
    subtree:add(f_transport, buffer(0, 0)):set_text(transport_name)

    local byte0 = buffer(0, 1):uint()
    local version = bit.rshift(byte0, 4)
    local phase = bit.band(byte0, 0x0F)
    local flags = buffer(1, 1):uint()
    local payload_length = buffer(2, 2):le_uint()

    subtree:add(f_version, buffer(0, 1), version)
    subtree:add(f_phase, buffer(0, 1), phase)
    subtree:add(f_flags, buffer(1, 1))
    subtree:add_le(f_payload_length, buffer(2, 2))

    local payload_available = packet_len - PREFIX_SIZE
    local payload_len = math.min(payload_length, payload_available)
    local payload_offset = PREFIX_SIZE

    if phase == PHASE_MSG1 then
        pinfo.cols.info:set("FIPS MSG1 (IK Handshake Initiator)")
        if payload_len < IDX_SIZE then
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "MSG1 payload too short for sender_idx")
            return packet_len
        end

        subtree:add_le(f_sender_idx, buffer(payload_offset, IDX_SIZE))
        local noise_off = payload_offset + IDX_SIZE
        local noise_len = payload_len - IDX_SIZE
        if noise_len > 0 then
            subtree:add(f_noise_payload, buffer(noise_off, noise_len))
        end
    elseif phase == PHASE_MSG2 then
        pinfo.cols.info:set("FIPS MSG2 (IK Handshake Responder)")
        if payload_len < (IDX_SIZE * 2) then
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "MSG2 payload too short for sender/receiver indices")
            return packet_len
        end

        subtree:add_le(f_sender_idx, buffer(payload_offset, IDX_SIZE))
        subtree:add_le(f_receiver_idx, buffer(payload_offset + IDX_SIZE, IDX_SIZE))
        local noise_off = payload_offset + (IDX_SIZE * 2)
        local noise_len = payload_len - (IDX_SIZE * 2)
        if noise_len > 0 then
            subtree:add(f_noise_payload, buffer(noise_off, noise_len))
        end
    elseif phase == PHASE_ESTABLISHED then
        if payload_len < (IDX_SIZE + COUNTER_SIZE) then
            pinfo.cols.info:set("FIPS Established (Malformed)")
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Established payload too short for receiver_idx/counter")
            return packet_len
        end

        subtree:add_le(f_receiver_idx, buffer(payload_offset, IDX_SIZE))
        subtree:add_le(f_counter, buffer(payload_offset + IDX_SIZE, COUNTER_SIZE))

        local enc_off = payload_offset + IDX_SIZE + COUNTER_SIZE
        local enc_len = payload_len - (IDX_SIZE + COUNTER_SIZE)
        if enc_len > 0 then
            subtree:add(f_noise_payload, buffer(enc_off, enc_len))
        end

        if enc_len == 17 then
            pinfo.cols.info:set("FIPS Heartbeat")
        else
            pinfo.cols.info:set("FIPS Established")
        end
    else
        pinfo.cols.info:set("FIPS Unknown Phase (0x" .. string.format("%02x", phase) .. ")")
    end

    if payload_available < payload_length then
        subtree:add_expert_info(
            PI_MALFORMED,
            PI_WARN,
            "Truncated payload: declared " .. payload_length .. " bytes, captured " .. payload_available .. " bytes"
        )
    end

    subtree:append_text(" [" .. phase_name(phase) .. "]")
    return packet_len
end

---------------------------------------------------------------------------
-- Heuristic: detect BLE L2CAP length-prefix framing
--
-- Over BLE L2CAP the payload is [2B BE length][FMP frame].
-- The 2-byte BE value should equal the remaining buffer length, and the
-- byte immediately after it should look like a valid FMP prefix (phase 0-2
-- in the low nibble).
---------------------------------------------------------------------------
local function detect_ble_prefix(buffer)
    local pktlen = buffer:len()
    if pktlen <= BLE_PREFIX_SIZE + PREFIX_SIZE then
        return false
    end
    local maybe_len = buffer(0, 2):uint()  -- big-endian uint16
    if maybe_len ~= pktlen - BLE_PREFIX_SIZE then
        return false
    end
    -- Verify the first byte after the prefix looks like a valid FMP header
    local first_fmp_byte = buffer(BLE_PREFIX_SIZE, 1):uint()
    local phase = bit.band(first_fmp_byte, 0x0F)
    return phase <= 0x02
end

---------------------------------------------------------------------------
-- Main dissector entry point
---------------------------------------------------------------------------
function p_fips.dissector(buffer, pinfo, tree)
    local pktlen = buffer:len()
    if pktlen == 0 then
        return 0
    end

    local mode = p_fips.prefs.transport_mode
    local is_ble = false

    if mode == TRANSPORT_AUTO then
        is_ble = detect_ble_prefix(buffer)
    elseif mode == TRANSPORT_BLE then
        is_ble = true
    end
    -- mode == TRANSPORT_UDP → is_ble stays false

    local subtree = tree:add(p_fips, buffer(), "FIPS FMP Frame")

    if is_ble then
        if pktlen < BLE_PREFIX_SIZE then
            pinfo.cols.protocol = "FIPS"
            pinfo.cols.info:set("FIPS Malformed (short BLE prefix)")
            subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "BLE payload too short for length prefix")
            return pktlen
        end

        local ble_len = buffer(0, 2):uint()
        subtree:add(f_ble_length, buffer(0, 2), ble_len)

        local fmp_buf = buffer:range(BLE_PREFIX_SIZE)
        local consumed = dissect_fmp(fmp_buf, pinfo, subtree, "BLE L2CAP")
        if consumed == 0 then
            return 0
        end
        return consumed + BLE_PREFIX_SIZE
    else
        return dissect_fmp(buffer, pinfo, subtree, "UDP")
    end
end

---------------------------------------------------------------------------
-- Registration
---------------------------------------------------------------------------

-- UDP port
local udp_table = DissectorTable.get("udp.port")
local current_udp_port = p_fips.prefs.udp_port
if current_udp_port > 0 then
    udp_table:add(current_udp_port, p_fips)
end

-- BLE L2CAP PSM (may not exist in older Wireshark builds)
local current_psm = p_fips.prefs.ble_psm
local l2cap_ok, l2cap_table = pcall(function()
    return DissectorTable.get("l2cap.psm")
end)
if l2cap_ok and l2cap_table and current_psm > 0 then
    l2cap_table:add(current_psm, p_fips)
end

-- Handle preference changes (re-register on different port/PSM)
function p_fips.prefs_changed()
    local new_udp = p_fips.prefs.udp_port
    if new_udp ~= current_udp_port then
        if current_udp_port > 0 then
            udp_table:remove(current_udp_port, p_fips)
        end
        if new_udp > 0 then
            udp_table:add(new_udp, p_fips)
        end
        current_udp_port = new_udp
    end

    if l2cap_ok and l2cap_table then
        local new_psm = p_fips.prefs.ble_psm
        if new_psm ~= current_psm then
            if current_psm > 0 then
                l2cap_table:remove(current_psm, p_fips)
            end
            if new_psm > 0 then
                l2cap_table:add(new_psm, p_fips)
            end
            current_psm = new_psm
        end
    end
end
