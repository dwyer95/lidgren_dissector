lidgren_proto = Proto("Lidgren", "Lidgren (lua)")

-- ip.addr==155.4.197.90 && ip.addr==192.168.1.196


local vs_funcs = {
    [0] = "Unconnected",
    [1] = "userUnreliable",

    [2] = "UserSequenced1",
    [3] = "UserSequenced1",
    [4] = "UserSequenced1",
    [5] = "UserSequenced1",
    [6] = "UserSequenced1",
    [7] = "UserSequenced1",
    [8] = "UserSequenced1",
    [9] = "UserSequenced1",
    [10] = "UserSequenced1",
    [11] = "UserSequenced1",
    [12] = "UserSequenced1",
    [13] = "UserSequenced1",
    [14] = "UserSequenced1",
    [15] = "UserSequenced1",
    [16] = "UserSequenced1",
    [17] = "UserSequenced1",
    [18] = "UserSequenced1",
    [19] = "UserSequenced1",
    [20] = "UserSequenced1",
    [21] = "UserSequenced1",
    [22] = "UserSequenced1",
    [23] = "UserSequenced1",
    [24] = "UserSequenced1",
    [25] = "UserSequenced1",
    [26] = "UserSequenced1",
    [27] = "UserSequenced1",
    [28] = "UserSequenced1",
    [29] = "UserSequenced1",
    [30] = "UserSequenced1",
    [31] = "UserSequenced1",
    [32] = "UserSequenced1",
    [33] = "UserSequenced32",

    [34] = "UserRealiableUnordered",
    [35] = "UserRealiableUnordered1",
    [36] = "UserRealiableUnordered",
    [37] = "UserRealiableUnordered",
    [38] = "UserRealiableUnordered",
    [39] = "UserRealiableUnordered",
    [40] = "UserRealiableUnordered",
    [41] = "UserRealiableUnordered",
    [42] = "UserRealiableUnordered",
    [43] = "UserRealiableUnordered",
    [44] = "UserRealiableUnordered",
    [45] = "UserRealiableUnordered",
    [46] = "UserRealiableUnordered",
    [47] = "UserRealiableUnordered",
    [48] = "UserRealiableUnordered",
    [49] = "UserRealiableUnordered",
    [50] = "UserRealiableUnordered",
    [51] = "UserRealiableUnordered",
    [52] = "UserRealiableUnordered",
    [53] = "UserRealiableUnordered",
    [54] = "UserRealiableUnordered",
    [55] = "UserRealiableUnordered",
    [56] = "UserRealiableUnordered",
    [57] = "UserRealiableUnordered",
    [58] = "UserRealiableUnordered",
    [59] = "UserRealiableUnordered",
    [60] = "UserRealiableUnordered",
    [61] = "UserRealiableUnordered",
    [62] = "UserRealiableUnordered",
    [63] = "UserRealiableUnordered",
    [64] = "UserRealiableUnordered",
    [65] = "UserRealiableUnordered",
    [66] = "UserRealiableUnordered32",


    [67] = "UserReliableOrdered1",
    [68] = "UserReliableOrdered2",
	[69] = "UserReliableOrdered3",
    [70] = "UserReliableOrdered3",
    [71] = "UserReliableOrdered3",
    [72] = "UserReliableOrdered3",
    [73] = "UserReliableOrdered3",
    [74] = "UserReliableOrdered3",
    [75] = "UserReliableOrdered3",
    [76] = "UserReliableOrdered3",
    [77] = "UserReliableOrdered3",
    [78] = "UserReliableOrdered3",
    [79] = "UserReliableOrdered3",
    [80] = "UserReliableOrdered3",
    [81] = "UserReliableOrdered3",
    [82] = "UserReliableOrdered3",
    [83] = "UserReliableOrdered3",
    [84] = "UserReliableOrdered3",
    [85] = "UserReliableOrdered3",
    [86] = "UserReliableOrdered3",
    [87] = "UserReliableOrdered3",
    [88] = "UserReliableOrdered3",
    [89] = "UserReliableOrdered3",
    [90] = "UserReliableOrdered3",
    [91] = "UserReliableOrdered3",
    [92] = "UserReliableOrdered3",
    [93] = "UserReliableOrdered3",
    [94] = "UserReliableOrdered3",
    [95] = "UserReliableOrdered3",
    [96] = "UserReliableOrdered3",
    [97] = "UserReliableOrdered3",
    [98] = "UserReliableOrdered32",

    [99] = "Unused1",
    [100] = "Unused1",
    [101] = "Unused1",
    [102] = "Unused1",
    [103] = "Unused1",
    [104] = "Unused1",
    [105] = "Unused1",
    [106] = "Unused1",
    [107] = "Unused1",
    [108] = "Unused1",
    [109] = "Unused1",
    [110] = "Unused1",
    [111] = "Unused1",
    [112] = "Unused1",
    [113] = "Unused1",
    [114] = "Unused1",
    [115] = "Unused1",
    [116] = "Unused1",
    [117] = "Unused1",
    [118] = "Unused1",
    [119] = "Unused1",
    [120] = "Unused1",
    [121] = "Unused1",
    [122] = "Unused1",
    [123] = "Unused1",
    [124] = "Unused1",
    [125] = "Unused1",
    [126] = "Unused1",
    [127] = "Unused29",


    [128] = "LibraryError",
    [129] = "Ping",	
    [130] = "Pong",
    [131] = "Connect",
    [132] = "ConnectResponse",
    [133] = "ConnectionEstablishes",
    [134] = "Acknowledge",
    [135] = "Disconnect",
    [136] = "Discovery",
    [137] = "DiscoveryResponse",
    [138] = "NatPunchMessage",
    [139] = "NatIntroductio",
    [142] = "NatIntroductionConfirmRequest",
    [143] = "NatIntroductionConfirmed",
    [140] = "ExpantMTURequest",
    [141] = "ExpandMTUSuccess"
    
}

-- declaring header fields

-- f_func, abbreviated for filters, function or func?
local f_func = ProtoField.uint8("lidgren.function", "Function", base.DEC, vs_funcs) 
local f_mseq = ProtoField.uint16("lidgren.mseq", "MessageSequence", base.DEC_HEX, nil, 65534) 
--65279
local f_fragm= ProtoField.uint16("lidgren.fragm", "Fragmented", base.DEC, nil, 1) --, 256
local f_len  = ProtoField.uint16("lidgren.len", "Payload Length", base.DEC_HEX)

lidgren_proto.fields = {f_func, f_mseq, f_len, f_fragm}

-- the dissection function
function lidgren_proto.dissector(buffer, pinfo, tree)

    pinfo.cols['protocol'] = "Lidgren"
    
    local tree_lidgren = tree:add(lidgren_proto, buffer())
    local offset = 0

    local tree_header = tree_lidgren:add(buffer(offset, 5), "Header")
    -- Första byten i headern är function
    tree_header:add(f_func, buffer(offset, 1))
    -- Andra och tredje byten i headern: message sequence number, kanske

    tree_header:add_le(f_mseq, buffer(offset +1, 2))-- buffer(offset + 1, 2))
    tree_header:add_le(f_fragm, buffer(offset + 1, 2))
    -- Fjärde och femte byten i headern: längden på meddelandet, incremented by 8.
    tree_header:add_le(f_len, buffer(offset + 3, 2))

    
    local func_code = buffer(offset, 1):uint()
    
    offset = offset+5

    -- Puts function name from table into info column in wireshark
    pinfo.cols['info'] = vs_funcs[func_code]

    --if func_code == 67 then
        -- UserReliableOrdered1 (actual msg)
        --tree_header:add()
    
    --end
end

local function heuristic_checker(buffer, pinfo, tree)

    length = buffer:len()
    if length < 5 then return false end

    if length > 1413 then return false end

    local potential_msg_id = buffer(0,1):uint()
    if potential_msg_id < 141
    then
        lidgren_proto.dissector(buffer, pinfo, tree)
        return true
    else return false end
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")
-- register the protocol to port 14242
--udp_table:add(14242, lidgren_proto)


-- Fragmentation/sequence number division
-- Endian

lidgren_proto:register_heuristic("udp", heuristic_checker)

