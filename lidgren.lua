lidgren_proto = Proto("Lidgren", "Lidgren (lua)")

-- ip.addr==155.4.197.90 && ip.addr==192.168.1.196


local vs_funcs = {
    [0] = "Unconnected",
    [1] = "userUnreliable",

	-- Lots more	

    [67] = "UserReliableOrdered1",
    [68] = "UserReliableOrdered2",
	[69] = "UserReliableOrdered3",

    [129] = "Ping",	
    [130] = "Pong",
    [131] = "Connect",
    [132] = "ConnectResponse",
    [133] = "ConnectionEstablishes",
    [134] = "Acknowledge",
    [135] = "Disconnect",
    [136] = "Discovery",
    [137] = "DiscoveryResponse",
    [138] = "NatPunchMessage"

	-- More here too
}

-- declaring header fields

-- f_func, abbreviated for filters, function or func?
local f_func = ProtoField.uint8("lidgren.function", "Function", base.DEC, vs_funcs) 
local f_mseq = ProtoField.uint16("lidgren.mseq", "Message Sequence", base.DEC) --65279
--local f_fragm= ProtoField.bool("lidgren.fragm", "Fragmented", base.DEC) --, 256
local f_len  = ProtoField.uint16("lidgren.len", "Length", base.DEC)

lidgren_proto.fields = {f_func, f_len}

-- the dissection function
function lidgren_proto.dissector(buffer, pinfo, tree)

    pinfo.cols['protocol'] = "Lidgren"
    
    local tree_lidgren = tree:add(lidgren_proto, buffer())
    local offset = 0

    local tree_header = tree_lidgren:add(buffer(offset, 5), "Header")
    -- Första byten i headern är function
    tree_header:add(f_func, buffer(offset, 1))
    -- Andra och tredje byten i headern: message sequence number, kanske
    tree_header:add(f_mseq, buffer(offset + 1, 2))
    --tree_header:add(f_fragm, buffer(offset + 1, 2))
    -- Fjärde och femte byten i headern: längden på meddelandet, incremented by 8.
    tree_header:add(f_len, buffer(offset + 3, 2))

    offset = offset+5

    local func_code = buffer(offset, 1):uint()

    -- Puts function name from table into info column in wireshark
    pinfo.cols['info'] = vs_funcs[func_code]

    --if func_code == 67 then
        -- UserReliableOrdered1 (actual msg)
        --tree_header:add()
    
    --end
end

-- load the udp port table
udp_table = DissectorTable.get("udp.port")
-- register the protocol to port 14242
udp_table:add(14242, lidgren_proto)
