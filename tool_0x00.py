#!/usr/bin/env python2

import os
import sys
import re
import pefile
from Crypto.Cipher import ARC4
import winappdbg
from winappdbg import Process, win32, HexDump

def RC4_dec(key, msg):
	return ARC4.new(key).decrypt(msg)

	
if len(sys.argv) < 2:
	print "Provide PID"
	exit()

system = winappdbg.System()
system.request_debug_privileges()
system.scan_processes()


pid = int(sys.argv[1])
process = Process(pid)
memory_map = process.get_memory_map()

for mM in memory_map: 
	if mM.Protect == win32.PAGE_EXECUTE_READWRITE:
		base_addr = mM.baseAddress
		reg_size = mM.RegionSize

		#pattern = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?0 ?4 ?? 00 ?? 00 00 00"
		
		pattern = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?0 ?4 ?? 00 ?? 00 00 00 ?? ?? ?? ?? ?? ?? ?? ??"
		
		f_data = process.search_hexa( pattern, base_addr, base_addr + reg_size)
		
		try:
			enc_con_addr = f_data.next()[0] + 0x18
		except:
			print "Not found"
			exit()
			
		print "[*] Encrypted config address: 0x%s" % HexDump.address(enc_con_addr, 32)
		enc_con = process.read(enc_con_addr, 0x2EF)
		RC4_key = process.read(enc_con_addr + 0x2EF, 0x39).rstrip('\x00')
		print "[*] RC4 key: %s" % RC4_key
		dec_con = RC4_dec(RC4_key, enc_con)
		conf = re.split("\x00+", dec_con)
		print "[*] Config: "
		for s in conf:
			print s
		
		print "[*] Dumping PE"
		PE_dump_path = "tmp_pe_dump"
		PE_dump = process.read(base_addr, reg_size)
		tmp_file = open(PE_dump_path, "wb+")
		tmp_file.write(PE_dump)
		tmp_file.close()
		
		pe = pefile.PE(PE_dump_path)
		
		for section in pe.sections:
			section.PointerToRawData = section.VirtualAddress
	
		new_exe_path = r"dumped_PE.bin"
		pe.write(new_exe_path)
		pe.close()
		os.remove(PE_dump_path)
		print "[*] Done"
		
