import sys
import struct
import pefile


def get_section_info_by_name(pe, section_name):
    for section in pe.sections:
        iter_name = section.Name.decode().rstrip('\x00')[1:] if section.Name.decode().startswith('.') else section.Name.decode().rstrip('\x00')
        if iter_name == section_name:
            section_info = {"begin_addr": section.PointerToRawData,
                            "end_addr": section.PointerToRawData + section.Misc_VirtualSize,
                            "data_size": section.Misc_VirtualSize}
            return section_info

def read_bytes_from_exe(exe_path, start_address, end_address):
        with open(exe_path, 'rb') as file:
            file.seek(start_address)
            byte_array = file.read(end_address - start_address)
            return byte_array

def write_data_to_exe(exe_path, data, offset):
    with open(exe_path, 'r+b') as f:
        f.seek(offset)
        f.write(data)

def calculate_crc(data):
    crc = 0xFFFFFFFF  # Initial CRC value
    for byte in data:
        crc ^= byte
        for i in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320  # CRC32 polynomial
            else:
                crc >>= 1
    return crc ^ 0xFFFFFFFF  # Final XOR

def main():
    exe_path = sys.argv[1]
    crc_section_name = "xDD"
    protected_section_name = "prot"
    pe = pefile.PE(exe_path)
    protected_section_info = get_section_info_by_name(pe, protected_section_name)
    byte_array = read_bytes_from_exe(exe_path, protected_section_info["begin_addr"], protected_section_info["end_addr"])
    protected_section_crc = calculate_crc(byte_array)
    protected_section_size = protected_section_info["data_size"]
    crc_section_info = get_section_info_by_name(pe, crc_section_name)
    protected_section_size_data = struct.pack('<I', protected_section_size)
    protected_section_crc_data = struct.pack('<I', protected_section_crc)
    write_data_to_exe(exe_path, protected_section_size_data, crc_section_info["begin_addr"])
    write_data_to_exe(exe_path, protected_section_crc_data, crc_section_info["begin_addr"] + 4)
    print(f"CRC32 of \".prot\" segment: 0x{protected_section_crc:08X}")

if __name__ == '__main__':
    main()
