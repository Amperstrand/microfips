-- FIPS FMP dissector for Wireshark/tshark (UDP/2121).
-- Usage examples:
--   tshark -X lua_script:tools/fips_dissector.lua -f "udp port 2121"
--   wireshark -X lua_script:tools/fips_dissector.lua

local p_fips = Proto("fips", "FIPS FMP")

local f_version = ProtoField.uint8("fips.version", "Version", base.HEX)
local f_phase = ProtoField.uint8("fips.phase", "Phase", base.HEX)
local f_flags = ProtoField.uint8("fips.flags", "Flags", base.HEX)
local f_payload_length = ProtoField.uint16("fips.payload_length", "Payload Length", base.DEC)
local f_sender_idx = ProtoField.uint32("fips.sender_idx", "Sender Index", base.HEX)
local f_receiver_idx = ProtoField.uint32("fips.receiver_idx", "Receiver Index", base.HEX)
local f_counter = ProtoField.uint64("fips.counter", "Counter", base.DEC)
local f_noise_payload = ProtoField.bytes("fips.noise_payload", "Encrypted Payload")

p_fips.fields = {
    f_version,
    f_phase,
    f_flags,
    f_payload_length,
    f_sender_idx,
    f_receiver_idx,
    f_counter,
    f_noise_payload,
}

local PHASE_ESTABLISHED = 0x00
local PHASE_MSG1 = 0x01
local PHASE_MSG2 = 0x02

local PREFIX_SIZE = 4
local IDX_SIZE = 4
local COUNTER_SIZE = 8

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

function p_fips.dissector(buffer, pinfo, tree)
    local packet_len = buffer:len()
    if packet_len < PREFIX_SIZE then
        pinfo.cols.protocol = "FIPS"
        pinfo.cols.info:set("FIPS Malformed (short prefix)")
        return 0
    end

    pinfo.cols.protocol = "FIPS"

    local subtree = tree:add(p_fips, buffer(), "FIPS FMP Frame")

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

DissectorTable.get("udp.port"):add(2121, p_fips)
