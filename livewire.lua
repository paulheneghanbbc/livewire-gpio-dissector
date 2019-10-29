-- Livewire audio postdissector
-- Paul Heneghan (BBC)
-- 2019-10-24 2239

-- declare some Fields to be read
ip_dst_f          = Field.new("ip.dst")
udp_dstport_f     = Field.new("udp.dstport")
udp_length_f      = Field.new("udp.length")
-- declare protocol
livewire_protocol = Proto("livewire","Livewire Postdissector")
-- create the fields
lw_channel_F      = ProtoField.string("livewire.channel","Livewire Channel")
lw_packet_time_F  = ProtoField.string("livewire.packet_type","Livewire Packet Type")
-- add the field to the protocol
livewire_protocol.fields = {lw_channel_F,lw_packet_time_F}

local packet_time = {
	["0"]         = "Unknown",
	["56"]        = "AES67 (6 samples, 125 us)",
	["92"]        = "Livestream (12 samples, 250 us)",
	["308"]       = "AES67 (48 samples, 1 ms)",
	["740"]       = "Standard Stream (120 samples, 2.5 ms)",
	["1460"]      = "Standard Stream (240 samples, 5 ms)"
}

-- create a function to "postdissect" each frame
function livewire_protocol.dissector(buffer,pinfo,tree)
    -- obtain the current values of the protocol fields
	local ip_dst = (ip_dst_f())
	local udp_dstport = (udp_dstport_f())
	local udp_length = (udp_length_f())

	if udp_dstport then
		local o1,o2,o3,o4 = tostring(ip_dst):match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
		if o1 == "239" and (o2 == "192" or o2 == "193") and tostring(udp_dstport) == "5004" then
			local ip_dst_num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
			local lw_channel = ip_dst_num % 65536
			local lw_packet_time = packet_time[tostring(udp_length)]
			local subtree = tree:add(livewire_protocol,"Livewire Channel: " .. lw_channel .. " [" .. packet_time[tostring(udp_length)] .. "]")
			subtree:add(lw_channel_F,lw_channel)
			if lw_packet_time then
				subtree:add(lw_packet_time_F,lw_packet_time)
			end
				pinfo.cols.protocol = livewire_protocol.name
				pinfo.cols.info:append(", Livewire " .. packet_time[tostring(udp_length)] .. ", Channel=" .. lw_channel)
		end

	end
end
-- register our protocol as a postdissector
register_postdissector(livewire_protocol)
