-- [[
--    Wireshark Dissector for Versa Networks SD-WAN packets
--    Author: jviyer@versa-networks.com
--
--    Copyright (c) 2018
--    www.versa-networks.com
-- ]]

local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- Set Debug to LEVEL_2 if verbose debugging is required.
local DEBUG = debug_level.DISABLED

local default_settings =
{
    debug_level  = DEBUG,
    port         = 4790,
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end

reset_debug_level()

dprint2("Wireshark version = ", get_version())
dprint2("Lua version = ", _VERSION)
local p_versavxlan = Proto("versavxlan","Versa Virtual eXtended LAN");
local p_versagre   = Proto("versagre", "Versa GRE Header");
local p_versampls  = Proto("versampls", "Versa MPLS Header");

-- Byte 0
local f_vxlan_flags           = ProtoField.uint8("versavxlan.flags","Flags", base.HEX)
local f_vxlan_flag_o          = ProtoField.bool("versavxlan.flags.oam","O Flag",8, {"OAM data", "Not OAM data"}, 0x01)
local f_vxlan_rsvd2           = ProtoField.uint8("versavxlan.flags.rsvd2","Reserved", base.HEX, nil, 0x02)
local f_vxlan_flag_p          = ProtoField.bool("versavxlan.flags.p","P Flag",8, {"Next Proto present", "Next Proto NOT present"}, 0x04)
local f_vxlan_flag_i          = ProtoField.bool("versavxlan.flags.i","I Flag",8, {"Valid VNI Tag present", "Valid VNI Tag NOT present"}, 0x08)
local f_vxlan_flag_v          = ProtoField.uint8("versavxlan.flags.version","Version", base.DEC, nil, 0x30)
local f_vxlan_rsvd1           = ProtoField.uint8("versavxlan.flags.rsvd","Reserved", base.HEX, nil, 0xc0)

-- Byte 1
local f_vxlan_flags2          = ProtoField.uint8("versavxlan.flags2","Flags2", base.HEX)
local f_vxlan_flags2_v4       = ProtoField.bool("versavxlan.flags2.v4","V4",8, {"V4 data", "NOT V4 data"}, 0x01)
local f_vxlan_flags2_v6       = ProtoField.bool("versavxlan.flags2.v6","V6",8, {"V6 data", "NOT V6 data"}, 0x02)
local f_vxlan_flags2_trc      = ProtoField.bool("versavxlan.flags2.trc","Trace",8, {"Trace", "Don't Trace"}, 0x04)
local f_vxlan_flags2_crc      = ProtoField.bool("versavxlan.flags2.crc","CRC",8, {"CRC present", "No CRC"}, 0x08)
local f_vxlan_flags2_ent      = ProtoField.bool("versavxlan.flags2.ent","Entropy",8, {"Entropy", "Entropy not present"}, 0x40)
local f_vxlan_flags2_sdwan    = ProtoField.bool("versavxlan.flags2.sdwan","SDWAN",8, {"Versa SD-WAN", "Not SD-WAN"}, 0x80)

-- Byte 2
local f_vxlan_wqid            = ProtoField.uint8("versavxlan.wqid", "WQ ID", base.DEC)

-- Byte 3
local f_vxlan_nextp           = ProtoField.uint8("versavxlan.nextp","Next Proto",base.DEC)

-- Byte 4 to 6
local f_vxlan_vni             = ProtoField.uint24("versavxlan.vni","VNI",base.HEX)

-- Byte 7
local f_vxlan_flags3          = ProtoField.uint8("versavxlan.flags3","Flags3", base.HEX)
local f_vxlan_win             = ProtoField.uint8("versavxlan.flags3.window","Window", base.DEC, nil, 0xC0)
local f_vxlan_tc              = ProtoField.uint8("versavxlan.flags3.tc","TC", base.DEC, nil, 0x30)
local f_vxlan_rsvd4           = ProtoField.uint8("versavxlan.flags3.rsvd","Reserved", base.DEC, nil, 0x0F)

local f_gre_flags = ProtoField.uint16("versagre.gre_flags", "GRE-Flags", base.HEX)
local f_gre_proto = ProtoField.uint16("versagre.gre_proto", "GRE-Proto", base.DEC)

local f_mpls_label_flags = ProtoField.uint24("versampls.mpls_label_flags", "MPLS-Label-Flags", base.HEX)
local f_mpls_label	  = ProtoField.uint24("versampls.mpls_label_flags.mpls_label", "MPLS-Label", base.DEC, nil, 0xFFFFF0)
local f_mpls_exp	  = ProtoField.uint24("versampls.mpls_label_flags.mpls_exp", "MPLS-EXP", base.DEC, nil, 0x00000E)
local f_mpls_bos	  = ProtoField.uint24("versampls.mpls_label_flags.mpls_bos", "MPLS-BOS", base.DEC, nil, 0x000001)
local f_mpls_ttl	  = ProtoField.uint8("versampls.mpls_ttl", "MPLS-TTL", base.DEC)

local data_dis = Dissector.get("data")

local VXLAN_HDR_LEN = 8
local ESP_HDR_LEN   = 8
local GRE_HDR_LEN   = 4
local MPLS_HDR_LEN  = 4
local GRE_PROTO_OFF = 2

--   /*
--    * Assigned GPE protocols
--    */
--    VXLAN_PROTO_V1_RSVD               = 0x0,
--    VXLAN_PROTO_V1_IP                 = 0x1,
--    VXLAN_PROTO_V1_IP6                = 0x2,
--    VXLAN_PROTO_V1_ETH                = 0x3,
--    VXLAN_PROTO_V1_NSH                = 0x4,
--    VXLAN_PROTO_V1_MPLS               = 0x5,
--
--    /*
--     * Unassigned VXLAN GPE protocols...temporary assignment
--     */
--    VXLAN_PROTO_V1_ESP                = 0xFC,
--    VXLAN_PROTO_V1_GRE                = 0xFD,
--    VXLAN_PROTO_V1_VMLH               = 0xFE,
--    VXLAN_PROTO_V1_MAX                = 0xFF

local success, eth_dissector = pcall(Dissector.get, "eth_withoutfcs")
if not success or not eth_dissector then
    eth_dissector = Dissector.get("eth")
end

local vxlan_proto_dis = {
    [0] = Dissector.get("data"),
    [1] = Dissector.get("ip"),
    [2] = Dissector.get("ipv6"),
    [3] = eth_dissector,
    [5] = Dissector.get("mpls"),
    [0xFC] = Dissector.get("esp"),
    [0xFE] = Dissector.get("mpls"),
}

local vxlan_proto_str = {
    [0] = "data",
    [1] = "ip",
    [2] = "ipv6",
    [3] = "eth",
    [4] = "data",
    [5] = "mpls",
    [0xFC] = "esp",
    [0xFD] = "gre",
    [0xFE] = "mpls",
    [0xFF] = "data",
}

local vxlan_next_proto_hdrlen = {
    [1] = 20,
    [2] = 40,
    [3] = 14,
    [5] = 4,
    [0xFC] = 8,
    [0xFE] = 4,
}

p_versavxlan.fields = {f_vxlan_flags, f_vxlan_flag_o, f_vxlan_rsvd2, f_vxlan_flag_p,
                       f_vxlan_flag_i, f_vxlan_flag_v, f_vxlan_rsvd1,
                       f_vxlan_flags2, f_vxlan_flags2_v4, f_vxlan_flags2_v6,
                       f_vxlan_flags2_trc, f_vxlan_flags2_crc, f_vxlan_flags2_ent, f_vxlan_flags2_sdwan,
                       f_vxlan_wqid, f_vxlan_nextp, f_vxlan_vni,
                       f_vxlan_flags3, f_vxlan_win, f_vxlan_tc, f_vxlan_rsvd4}
p_versagre.fields = {f_gre_flags, f_gre_proto}
p_versampls.fields = {f_mpls_label_flags, f_mpls_label, f_mpls_exp, f_mpls_bos, f_mpls_ttl}

function versa_mpls_gre_dissector(buf, pinfo, root)
    dprint2("versa_mpls_gre_dissector called")

    local pos = 0
    local gre_proto = buf(GRE_PROTO_OFF, 2):uint()
    if (gre_proto ==  0x8847) then
        local mpls_dis = Dissector.get("mpls")
        local mpls_label
        local mpls_bos = 0
        local mpls_tree
        local flagrange
        local f
        local gre_tree = root:add(p_versagre, buf:range(0,4))

        pos = GRE_HDR_LEN

        gre_tree:add(f_gre_flags, buf:range(0,2))
        gre_tree:add(f_gre_proto, buf:range(2,2))

        next_proto_eth = 0
        while (mpls_bos == 0) do

            mpls_tree  = root:add(p_versampls, buf:range(pos,4))
            flagrange  = buf:range(pos, 3)
            f = mpls_tree:add(f_mpls_label_flags, flagrange)
            f:add(f_mpls_label, flagrange)
            f:add(f_mpls_exp, flagrange)
            f:add(f_mpls_bos, flagrange)
            mpls_tree:add(f_mpls_ttl, buf:range(pos + 3, 1))
            mpls_label = buf(pos, 4):uint()
            mpls_label = bit.rshift(mpls_label, 12)
            mpls_bos   = buf(pos + 2, 1):uint()
            mpls_bos   = bit.band(mpls_bos, 0x01)

            dprint2("p_versavxlan.dissector called, mpls label, bos", mpls_label, mpls_bos)
            if (mpls_label == 17) then
                next_proto_eth = 1
            end
            pos = pos + MPLS_HDR_LEN
        end
        if (next_proto_eth == 1) then
            local eth_dis = Dissector.get("eth")
            eth_dis:call(buf(pos):tvb(), pinfo, root)
        else
            local ip_dis = Dissector.get("ip")
            ip_dis:call(buf(pos):tvb(), pinfo, root)
        end
    else
        data_dis:call(buf(pos):tvb(), pinfo, root)
    end
end

-- Patch (23.1.2): next-proto 0xFB = Versa VMLH header; flag byte @off 3 => 0x05 clear / 0xfc encrypted
local p_versavmlh = Proto("versavmlh","Versa VMLH (SD-WAN metadata)")
local f_vmlh_flag = ProtoField.uint8("versavmlh.flag","VMLH flag (0x05=clear 0xfc=enc)",base.HEX)
p_versavmlh.fields = { f_vmlh_flag }

function versa_vmlh_fb(buf, pinfo, root)
    local flag = buf(3,1):uint()
    if flag == 0x05 then
        local t = root:add(p_versavmlh, buf(0,16)); t:add(f_vmlh_flag, buf(3,1)); t:append_text(", CLEAR (no ESP), 16B")
        Dissector.get("ip"):call(buf(16):tvb(), pinfo, root)
    elseif flag == 0xfc then
        local t = root:add(p_versavmlh, buf(0,12)); t:add(f_vmlh_flag, buf(3,1)); t:append_text(", ENCRYPTED, 12B -> ESP")
        Dissector.get("esp"):call(buf(12):tvb(), pinfo, root)
    else
        data_dis:call(buf:tvb(), pinfo, root)
    end
end

function p_versavxlan.dissector(buf, pinfo, root)

    dprint2("p_versavxlan.dissector called")

    pinfo.cols.protocol:set("Versa-VXLAN")

    local t = root:add(p_versavxlan, buf:range(0,8))

    local flagrange = buf:range(0,1)
    local f = t:add(f_vxlan_flags, flagrange)
    f:add(f_vxlan_flag_o, flagrange)
    f:add(f_vxlan_flag_p, flagrange)
    f:add(f_vxlan_flag_i, flagrange)
    f:add(f_vxlan_flag_v, flagrange)

    flagrange = buf:range(1,1)
    local f2 = t:add(f_vxlan_flags2, flagrange)
    f2:add(f_vxlan_flags2_v4, flagrange)
    f2:add(f_vxlan_flags2_v6, flagrange)
    f2:add(f_vxlan_flags2_trc, flagrange)
    f2:add(f_vxlan_flags2_crc, flagrange)
    f2:add(f_vxlan_flags2_ent, flagrange)
    f2:add(f_vxlan_flags2_sdwan, flagrange)

    t:add(f_vxlan_wqid, buf:range(2,1))
    t:add(f_vxlan_nextp, buf:range(3,1))
    t:add(f_vxlan_vni, buf:range(4,3))

    local flagrange2 = buf:range(7,1)
    local f3 = t:add(f_vxlan_flags3, flagrange2)
    f3:add(f_vxlan_win, flagrange2);
    f3:add(f_vxlan_tc, flagrange2);
    f3:add(f_vxlan_rsvd4, flagrange2);

    t:append_text(", VNI: 0x" .. string.format("%x", buf(4, 3):uint()))

    local next_proto_str = vxlan_proto_str[buf(3, 1):uint()]
    t:append_text(", Next Proto: 0x" .. string.format("%x(%s)",
    buf(3, 1):uint(), next_proto_str))

    t:append_text(", WQ ID: " .. string.format("%u", buf(2, 1):uint()))

    local proto = buf(3,1):uint()
    local inner_dis = vxlan_proto_dis[proto]

    pos = VXLAN_HDR_LEN
    if inner_dis ~= nil then
        inner_dis:call(buf(pos):tvb(), pinfo, root)
        if (proto == 0xFC) then
            versa_mpls_gre_dissector(buf(pos + ESP_HDR_LEN):tvb(), pinfo, root)
        end
    else
        if (proto == 0xFD) then
            versa_mpls_gre_dissector(buf(pos):tvb(), pinfo, root)
        elseif (proto == 0xFB) then
            versa_vmlh_fb(buf(pos):tvb(), pinfo, root)
        else
            data_dis:call(buf(pos):tvb(), pinfo, root)
        end
    end

end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(4790, p_versavxlan)
