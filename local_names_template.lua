-- Rename this file as local_names.lua and place in the Wireshark plugins folder
-- Use a spreadsheed to generate the gpo and gpi values as shown below
-- If the livewire channel is 18204 and the GPO number is 5, then the index is 182045
-- Blank ("") entries are OK
-- There is basic error trapping for missing entries in the dissector

gpo = {}
gpi = {}				

gpo[182044] = 'St1 Console CP4 Fader Open'
gpo[182045] = 'St1 Console CP4 Start'
gpi[182044] = 'srvdira1001 St1 CP4 Playing'
gpi[182045] = 'srvdira1001 St1 CP4 Ready'
-- etc.