-- Lua Wireshark Dissector for Telos/Axia Livewire GPIO  
-- Author: Paul Heneghan (paul.heneghan@bbc.co.uk)
-- Date: 27th October 2019
--
-- To use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled
--    with Lua.
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see
--    Personal and Global plugin directories.  
-- 3) Optionally, install a local_names.lua file in the same directory. This allows the dissector
--    to show local detail about the GPIOs (typically the device name that generates it and the
--    function of the GPIO. It is easy to generate this file from a spreadsheet.
--    If this file is in the Personal rather than the Global plugin directory, you will need to
--    amend the 'if file_exists' statement below to contain the complete path name - remember to
--    escape any slashes in the path.
-- 4) The dissector will register UDP ports 2055 and 2060.
-- 5) After putting this dissector in the proper folder, "About Wireshark/Plugins" should list
--    - livewire-gpio.lua
--    - local_names.lua
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- Details of Livewire GPIO specification
-- Usually 70 bytes (74 if 802.1Q tagged) long for a single item GPIO messages
-- Ethernet - 14 bytes
-- (802.1Q - 4 bytes)
-- IPv4 - 20 bytes
-- UDP - 8 bytes
-- R/UDP - 16 bytes
-- CMsg - usually 12 bytes for simple single-item GPIO messages
--
-- The dissector decodes the UDP payload as follows:
-- R/UDP header (bytes 1-4 = 0x03000207, ignore bytes 5-16)
-- Message ID (four bytes - WRNI, WRIN, READ, INDI, STAT, NEST)
-- Item Count (two bytes)
-- Item Tag (four bytes - LCID, GAIN, MUTE, 0xfffffffd, etc.
--   if LCID (Logic Circuit ID),
--     Byte 1 = 0
--     Byte 2,3 = LPID (Logic Port ID = Livewire Channel)
--     Byte 4 = GPIO Circuit
--       GPO circuit has values 4-8  (subtract from 9 for Application GPO number)
--       GPI circuit has values 9-13 (subtract from 14 for Application GPI  number)
-- Item data type (1=DWord, 2=String, 7=Byte, 8=Word, some variables)
-- Item data length (needed if variable length data used)
-- Item value (length as determined by Item data type and data length)
--   if LCID
--     0000 0000 = Low        (steady)
--     000x xxxx = Pulse Low  (duration = x * 250 ms)
--     0100 0000 = High       (ready)
--     010x xxxx = Pulse High (duration = x * 250 ms)
--     1000 0000 = Low        (steady)
--     10xx xxxx = Pulse Low  (duration = x * 10 ms)
--     1100 0000 = High       (steady)
--     11xx xxxx = Pulse High (duration = x * 10 ms)
--   if GAIN,
--     GAIN in 0.1 dB steps (two's complement, so 0x001E = +3.0 dB)
--   if MUTE
--     0x00 = Mute
--   if 0xfffffffd (Message class for transaction control)
--     1 = Command
--     2 = Response
-- See 'Livewire GPIO Protocol - 2016-02-10.pdf' for complete specification 

-- Define protocol - including name that appears (in capitals) in protocol field of Packet List
lwgpio_protocol     = Proto("lw-gpio",  "Livewire GPIO Protocol")

-- Message type lookup
local message_type = {
	["WRNI"]  = "Write",
	["WRIN"]  = "Write",
	["READ"]  = "Read",
	["INDI"]  = "Indicate",
	["STAT"]  = "Status",
	["NEST"]  = "Nest Container"
}

-- Message type details lookup
local message_type_details = {
	["WRNI"]  = "Write value - returning the value indication is not requested",
	["WRIN"]  = "Write value - returning the value indication is requested",
	["READ"]  = "Read value",
	["INDI"]  = "Value indication",
	["STAT"]  = "Status indication",
	["NEST"]  = "No operation - container for nested messages"
}

-- Data type lookup
local data_type = {
	[1]  = "Dword",
	[2]  = "String",
	[3]  = "ByteArray",
	[4]  = "WordArray",
	[5]  = "DwordArray",
	[6]  = "Msg",
	[7]  = "Byte",
	[8]  = "Word",
	[9]  = "Qword",
	[10] = "QwordArray"
}

-- Circuit to gpio lookup
local gpio = {
	[4]  = 5,
	[5]  = 4,
	[6]  = 3,
	[7]  = 2,
	[8]  = 1,
	[9]  = 5,
	[10] = 4,
	[11] = 3,
	[12] = 2,
	[13] = 1
}
	
-- Protocol Fields
local pf_rudp              = ProtoField.bytes   ("livewire.rudp",             "R/UDP"                )
local pf_message_id        = ProtoField.string  ("livewire.message_id",       "Message ID"           )
local pf_item_count        = ProtoField.uint16  ("livewire.message_length",   "Item Count"           )
local pf_item_tag_id       = ProtoField.uint32  ("livewire.item_tag_id",      "Tag ID",      base.HEX)
local pf_item_lcid         = ProtoField.uint32  ("livewire.item_lcid",        "LCID",        base.HEX)
local pf_item_lpid         = ProtoField.uint16  ("livewire.item_lpid",        "LPID",        base.DEC)
local pf_item_circuit      = ProtoField.uint8   ("livewire.circuit",          "Circuit"              )
local pf_item_data_type    = ProtoField.uint8   ("livewire.item_data_type",   "Item Data Type"       )
local pf_item_data_length  = ProtoField.uint16  ("livewire.item_data_length", "Item Data Length"     )
local pf_item_data         = ProtoField.uint8   ("livewire.item_data",        "Item Data",   base.HEX)

local pf_item_flags        = ProtoField.new     ("Item Data",    "livewire.flags",                ftypes.UINT8,   nil,                 base.HEX                           )
local pf_flag_bits0to6     = ProtoField.new     ("GPO",          "livewire.flags.steady",         ftypes.BOOLEAN, {"High","Low"},      8,        0x7F, "Steady:"          )
local pf_flag_bit7         = ProtoField.new     ("Pulse Shape",  "livewire.flags.pulse_shape",    ftypes.BOOLEAN, {"Plain","Special"}, 8,        0x80, "Pulse shape code:")
local pf_flag_bit6         = ProtoField.new     ("Polarity",     "livewire.flags.pulse_polarity", ftypes.BOOLEAN, {"High","Low"},      8,        0x40, "Pulse High/Low:"  )
local pf_flag_bits5and6    = ProtoField.new     ("Polarity",     "livewire.flags.pulse_duration", ftypes.BOOLEAN, {"High","Low"},      8,        0x60, "Pulse Length:"    )
local pf_flag_bits0to5     = ProtoField.new     ("Duration",     "livewire.flags.pulse_duration", ftypes.UINT8,   nil,                 base.DEC, 0x3F, "Pulse Duration:"  )
local pf_flag_bits0to4     = ProtoField.new     ("Duration",     "livewire.flags.pulse_duration", ftypes.UINT8,   nil,                 base.DEC, 0x1F, "Pulse Duration:"  )

local gpio_type = "Unknown"
local local_information
local local_information_state
local subtree

-- Pass protocol fields to Dissector
lwgpio_protocol.fields = {
	pf_rudp, pf_message_id, pf_item_count, pf_item_tag_id, 
	pf_item_lcid, pf_item_lpid, pf_item_circuit, pf_item_data_type, 
	pf_item_data_length, pf_item_data, pf_item_flags,
	pf_flag_bits0to6, pf_flag_bit7, pf_flag_bit6, pf_flag_bits5and6, pf_flag_bits0to5, pf_flag_bits0to4
}

-- Dissector function
function lwgpio_protocol.dissector(buffer, pinfo, tree)
	local local_information = ""
	local local_information_state = ""
	
	local length = buffer:len()
	if length == 0 then return end
	
	local fetch_rudp_dword      = buffer(0,4):uint()
	if fetch_rudp_dword ~= 0x03000207 then return end

	-- Pop "LW-GPIO" into protocol field in Packet List pane
	pinfo.cols.protocol = lwgpio_protocol.name

	-- Prefetch fields to perform some calculations
	local fetch_message_id   = buffer(16,4):string()
	local fetch_item_count   = buffer(20,2):uint()
	local fetch_item_lcid    = buffer(22,4):uint()
	local fetch_item_check   = buffer(22,1):uint()
	local fetch_item_lpid    = buffer(23,2):uint()
	local fetch_item_circuit = buffer(25,1):uint()
	local fetch_data_type    = buffer(26,1):uint()
	local fetch_data         = buffer(27,1):uint()

	-- Bodge for 2 item INDI packets (UDP payload = 34)
	if length == 34 then
		fetch_item2_tag       = buffer(28,4):uint()
		fetch_item2_data_type = buffer(32,1):uint()
		fetch_item2_data      = buffer(33,1):uint()
	end

	-- Calculations
	calc_gpo_state, calc_gpo_duration    = get_gpo_pulse(fetch_data)
	if fetch_item_circuit > 8 then
		gpio_type = "GPI"
	else
		gpio_type = "GPO"
	end
	
	if file_exists("C:\\Program Files\\Wireshark\\plugins\\local_names.lua") then
		if gpio_type == "GPI" then
			local_information = gpi[fetch_item_lpid*10+gpio[fetch_item_circuit]]
		else
			local_information = gpo[fetch_item_lpid*10+gpio[fetch_item_circuit]]
		end
		if local_information == nil then
			local_information = "No lookup in plugins\\local_names.lua"
			local_information_state = " [" .. local_information .. "]"
		else
			if fetch_message_id == "READ" then
				local_information_state = " [" .. local_information .. "]"
			else
				local_information_state = " [" .. local_information .. " = " .. calc_gpo_state .. calc_gpo_duration .. "]"
			end
		end
	end
	
	-- Build dissection tree
	if fetch_message_id == "READ" then
		subtree = tree:add(lwgpio_protocol, buffer(), "Livewire Protocol Data, " .. message_type[fetch_message_id] .. " " .. gpio_type .. " " .. fetch_item_lpid .. "." .. gpio[fetch_item_circuit] .. local_information_state)
	else
		subtree = tree:add(lwgpio_protocol, buffer(), "Livewire Protocol Data, " .. message_type[fetch_message_id] .. " " .. gpio_type .. " " .. fetch_item_lpid .. "." .. gpio[fetch_item_circuit] .. " = " .. fetch_data .. local_information_state)
	end
	subtree:add(pf_rudp, buffer(0,16)):append_text(" [First four bytes must be 0x03000207]")
	subtree:add(pf_message_id, buffer(16,4)):append_text(" [" .. message_type_details[fetch_message_id] .. "]")
	subtree:add(pf_item_count, buffer(20,2))
	subtree:add(pf_item_lcid, buffer(22,4)):append_text(" [Logic Circuit ID - decodes to GPO " .. fetch_item_lpid .. "." .. gpio[fetch_item_circuit] .. " - " .. local_information .. "]")
	subtree:add(pf_item_lpid, buffer(23,2)):append_text(" [Logic Port ID - possibly related to audio stream on 239.192." .. math.floor(fetch_item_lpid/256) .. "." .. (fetch_item_lpid % 256) .. "]")
	subtree:add(pf_item_circuit, buffer(25,1)):append_text(" [" .. gpio_type .. " " .. gpio[fetch_item_circuit] .. "]")
	subtree:add(pf_item_data_type, buffer(26,1)):append_text(" [" .. data_type[fetch_data_type] .. "]")

	-- Build flag child tree
	local flag_tree = subtree:add(pf_item_flags, buffer(27,1)):append_text(" [" .. calc_gpo_state .. calc_gpo_duration .. "]")
		if fetch_message_id == "READ" or fetch_message_id == "INDI" then
		elseif fetch_data == 0 or fetch_data == 64 or fetch_data == 128 or fetch_data == 192 then
			flag_tree:add(pf_flag_bit7, buffer(27,1))
			flag_tree:add(pf_flag_bits0to6, buffer(27,1))
		elseif bit.band(fetch_data,128) == 128 then
			flag_tree:add(pf_flag_bit7, buffer(27,1))
			flag_tree:add(pf_flag_bit6, buffer(27,1))
			flag_tree:add(pf_flag_bits0to5, buffer(27,1)):append_text(" [" .. bit.band(fetch_data,63)*0.01 .." seconds]")
		elseif bit.band(fetch_data,32) == 0 then
			flag_tree:add(pf_flag_bit7, buffer(27,1))
			flag_tree:add(pf_flag_bits5and6, buffer(27,1))
			flag_tree:add(pf_flag_bits0to4, buffer(27,1)):append_text(" [" .. bit.band(fetch_data,31)*0.25 .." seconds]")
		else
			flag_tree:add(pf_flag_bits0to7, buffer(27,1)):append_text(" [TBD]")
		end

	-- Bodge for 2 item INDI packets (UDP payload = 34)
	if length == (34) then
		if fetch_item2_tag == 0xfffffffd then
			subtree:add(pf_item_tag_id, buffer(28,4)):append_text(" [Message class for transaction control]")
		else
			subtree:add(pf_item_tag_id, buffer(28,4))
		end
		subtree:add(pf_item_data_type, buffer(32,1)):append_text(" [" .. data_type[buffer(32,1):uint()] .. "]")
		if fetch_item2_data == 1 then
			subtree:add(pf_item_data, buffer(33,1)):append_text(" [Command]")
		elseif fetch_item2_data == 2 then
			subtree:add(pf_item_data, buffer(33,1)):append_text(" [Response]")
		else
			subtree:add(pf_item_data, buffer(33,1))
		end
	end
	
	if fetch_message_id == "READ" then
		pinfo.cols.info = message_type[fetch_message_id] .. " " .. gpio_type .. " " .. fetch_item_lpid .. "." .. gpio[fetch_item_circuit] .. local_information_state
	else
		pinfo.cols.info = message_type[fetch_message_id] .. " " .. gpio_type .. " " .. fetch_item_lpid .. "." .. gpio[fetch_item_circuit] .. " = " .. fetch_data .. local_information_state
	end
end

-- Function to extract GPO pulse type, polarity and duration
get_gpo_pulse = function(gpo_value)
	local get_gpo_state = ""
	local get_gpo_duration = ""
	if fetch_message_id == "INDI" then
		if gpo_value == 0 then get_gpo_state = "Inactive"
		else get_gpo_state = "Active"
		end
	elseif fetch_message_id == "READ" then
		get_gpo_state = ""
	elseif (gpo_value == 0 or gpo_value == 128) then
		get_gpo_state = "Low"
	elseif (gpo_value == 64 or gpo_value == 192) then
		get_gpo_state = "High"
	elseif gpo_value < 32 then
		get_gpo_state = "Pulse Low"
		local x = gpo_value*0.25
		get_gpo_duration = " - " .. x .. " seconds"
	elseif (gpo_value > 64 and gpo_value < 96) then
		get_gpo_state = "Pulse High"
		get_gpo_duration = " - " .. (gpo_value-64)*0.25 .. " seconds"
	elseif (gpo_value > 128 and gpo_value < 192) then
		get_gpo_state = "Pulse Low"
		get_gpo_duration = " - " .. (gpo_value-128)*0.01 .. " seconds"
	elseif (gpo_value > 192) then
		get_gpo_state = "Pulse High"
		get_gpo_duration = " - " .. (gpo_value-192)*0.01 .. " seconds"	
	else
		get_gpo_state = "TBD"
	end
	return get_gpo_state, get_gpo_duration
end

-- Function to check file exists
function file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end
		
-- Register UDP ports 2055 and 2060
local udp_port = DissectorTable.get("udp.port")
udp_port:add(2055, lwgpio_protocol)
udp_port:add(2060, lwgpio_protocol)

