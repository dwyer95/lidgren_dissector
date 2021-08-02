lidgren_proto = Proto("Lidgren", "Lidgren (lua)")

local vs_funcs = {
    [0] = "Unconnected",
    [1] = "userUnreliable",

    [2] = "UserSequenced1",
    [3] = "UserSequenced2",
    [4] = "UserSequenced3",
    [5] = "UserSequenced4",
    [6] = "UserSequenced5",
    [7] = "UserSequenced6",
    [8] = "UserSequenced7",
    [9] = "UserSequenced8",
    [10] = "UserSequenced9",
    [11] = "UserSequenced10",
    [12] = "UserSequenced11",
    [13] = "UserSequenced12",
    [14] = "UserSequenced13",
    [15] = "UserSequenced14",
    [16] = "UserSequenced15",
    [17] = "UserSequenced16",
    [18] = "UserSequenced17",
    [19] = "UserSequenced18",
    [20] = "UserSequenced19",
    [21] = "UserSequenced20",
    [22] = "UserSequenced21",
    [23] = "UserSequenced22",
    [24] = "UserSequenced23",
    [25] = "UserSequenced24",
    [26] = "UserSequenced25",
    [27] = "UserSequenced26",
    [28] = "UserSequenced27",
    [29] = "UserSequenced28",
    [30] = "UserSequenced29",
    [31] = "UserSequenced30",
    [32] = "UserSequenced31",
    [33] = "UserSequenced32",

    [34] = "UserRealiableUnordered",
	
    [35] = "UserRealiableSequenced1",
    [36] = "UserRealiableSequenced2",
    [37] = "UserRealiableSequenced3",
    [38] = "UserRealiableSequenced4",
    [39] = "UserRealiableSequenced5",
    [40] = "UserRealiableSequenced6",
    [41] = "UserRealiableSequenced7",
    [42] = "UserRealiableSequenced8",
    [43] = "UserRealiableSequenced9",
    [44] = "UserRealiableSequenced10",
    [45] = "UserRealiableSequenced11",
    [46] = "UserRealiableSequenced12",
    [47] = "UserRealiableSequenced13",
    [48] = "UserRealiableSequenced14",
    [49] = "UserRealiableSequenced15",
    [50] = "UserRealiableSequenced16",
    [51] = "UserRealiableSequenced17",
    [52] = "UserRealiableSequenced18",
    [53] = "UserRealiableSequenced19",
    [54] = "UserRealiableSequenced20",
    [55] = "UserRealiableSequenced21",
    [56] = "UserRealiableSequenced22",
    [57] = "UserRealiableSequenced23",
    [58] = "UserRealiableSequenced24",
    [59] = "UserRealiableSequenced25",
    [60] = "UserRealiableSequenced26",
    [61] = "UserRealiableSequenced27",
    [62] = "UserRealiableSequenced28",
    [63] = "UserRealiableSequenced29",
    [64] = "UserRealiableSequenced30",
    [65] = "UserRealiableSequenced31",
    [66] = "UserRealiableSequenced32",

    [67] = "UserReliableOrdered1",
    [68] = "UserReliableOrdered2",
    [69] = "UserReliableOrdered3",
    [70] = "UserReliableOrdered4",
    [71] = "UserReliableOrdered5",
    [72] = "UserReliableOrdered6",
    [73] = "UserReliableOrdered7",
    [74] = "UserReliableOrdered8",
    [75] = "UserReliableOrdered9",
    [76] = "UserReliableOrdered10",
    [77] = "UserReliableOrdered11",
    [78] = "UserReliableOrdered12",
    [79] = "UserReliableOrdered13",
    [80] = "UserReliableOrdered14",
    [81] = "UserReliableOrdered15",
    [82] = "UserReliableOrdered16",
    [83] = "UserReliableOrdered17",
    [84] = "UserReliableOrdered18",
    [85] = "UserReliableOrdered19",
    [86] = "UserReliableOrdered20",
    [87] = "UserReliableOrdered21",
    [88] = "UserReliableOrdered22",
    [89] = "UserReliableOrdered23",
    [90] = "UserReliableOrdered24",
    [91] = "UserReliableOrdered25",
    [92] = "UserReliableOrdered26",
    [93] = "UserReliableOrdered27",
    [94] = "UserReliableOrdered28",
    [95] = "UserReliableOrdered29",
    [96] = "UserReliableOrdered30",
    [97] = "UserReliableOrdered31",
    [98] = "UserReliableOrdered32",

    [99] = "Unused1",
    [100] = "Unused2",
    [101] = "Unused3",
    [102] = "Unused4",
    [103] = "Unused5",
    [104] = "Unused6",
    [105] = "Unused7",
    [106] = "Unused8",
    [107] = "Unused9",
    [108] = "Unused10",
    [109] = "Unused11",
    [110] = "Unused12",
    [111] = "Unused13",
    [112] = "Unused14",
    [113] = "Unused15",
    [114] = "Unused16",
    [115] = "Unused17",
    [116] = "Unused18",
    [117] = "Unused19",
    [118] = "Unused20",
    [119] = "Unused21",
    [120] = "Unused22",
    [121] = "Unused23",
    [122] = "Unused24",
    [123] = "Unused25",
    [124] = "Unused26",
    [125] = "Unused27",
    [126] = "Unused28",
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
local f_func = ProtoField.uint8("lidgren.function", "Function", base.DEC, vs_funcs) 
local f_mseq = ProtoField.uint16("lidgren.mseq", "MessageSequence", base.DEC_HEX, nil, 65534) 
local f_fragm= ProtoField.uint16("lidgren.fragm", "Fragmented", base.DEC, nil, 1)
local f_len  = ProtoField.uint16("lidgren.len", "Payload Length", base.DEC_HEX)

lidgren_proto.fields = {f_func, f_mseq, f_len, f_fragm}

-- the dissection function
function lidgren_proto.dissector(buffer, pinfo, tree)

    pinfo.cols['protocol'] = "Lidgren"
    
    local tree_lidgren = tree:add(lidgren_proto, buffer())
    local offset = 0

    local tree_header = tree_lidgren:add(buffer(offset, 5), "Header")
	
    -- 1st byte in header = function code
    tree_header:add(f_func, buffer(offset, 1))

    --2nd and 3rd bytes = message sequence number, kanske
    tree_header:add_le(f_mseq, buffer(offset +1, 2))
    tree_header:add_le(f_fragm, buffer(offset + 1, 2))

    -- 4th and 5th bytes = msg length, incremented by 8.
    tree_header:add_le(f_len, buffer(offset + 3, 2))

    local func_code = buffer(offset, 1):uint()
    
    offset = offset+5

    -- puts function name from table into info column in wireshark
    pinfo.cols['info'] = vs_funcs[func_code]
end

-- checks if packet is of Lidgren protocol
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

udp_table = DissectorTable.get("udp.port")

lidgren_proto:register_heuristic("udp", heuristic_checker)
