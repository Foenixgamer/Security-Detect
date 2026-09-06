"""
Análisis de encabezados de archivos PE y ELF.
"""

import struct
import os

def analyze_pe_header(file_path):
    """
    Analiza el encabezado PE del archivo.
    
    Args:
        file_path (str): Ruta al archivo PE
    
    Returns:
        dict: Información extraída del encabezado PE
    """
    with open(file_path, 'rb') as f:
        # Saltar DOS header y leer NT header
        f.seek(0x3C)  # Offset al PE header
        pe_offset = struct.unpack('<I', f.read(4))[0]
        
        f.seek(pe_offset)
        signature = f.read(4)
        if signature != b'PE\x00\x00':
            raise ValueError("No es un archivo PE válido")
            
        # Leer COFF header (20 bytes)
        f.seek(pe_offset + 4)
        machine = struct.unpack('<H', f.read(2))[0]
        number_of_sections = struct.unpack('<H', f.read(2))[0]
        
        time_date_stamp = struct.unpack('<I', f.read(4))[0]
        pointer_to_symbol_table = struct.unpack('<I', f.read(4))[0]
        number_of_symbols = struct.unpack('<I', f.read(4))[0]
        size_of_optional_header = struct.unpack('<H', f.read(2))[0]
        characteristics = struct.unpack('<H', f.read(2))[0]
        
        return {
            "signature": signature.rstrip(b'\x00').decode('ascii'),
            "machine": hex(machine),
            "number_of_sections": number_of_sections,
            "time_date_stamp": time_date_stamp,
            "pointer_to_symbol_table": pointer_to_symbol_table,
            "number_of_symbols": number_of_symbols,
            "size_of_optional_header": size_of_optional_header,
            "characteristics": hex(characteristics)
        }

def analyze_elf_header(file_path):
    """
    Analiza el encabezado ELF del archivo (32 y 64 bits, little/big endian).
    
    Args:
        file_path (str): Ruta al archivo ELF
    
    Returns:
        dict: Información extraída del encabezado ELF
    """
    with open(file_path, 'rb') as f:
        e_ident = f.read(16)
        if e_ident[:4] != b'\x7fELF':
            raise ValueError("No es un archivo ELF válido")

        is_64 = e_ident[4] == 2          # EI_CLASS: 1 = 32-bit, 2 = 64-bit
        endian = e_ident[5]              # EI_DATA: 1 = little, 2 = big
        fmt = '<' if endian == 1 else '>'

        if is_64:
            fields = struct.unpack(fmt + 'HHIQQQIHHHHHH', f.read(48))
        else:
            fields = struct.unpack(fmt + 'HHIIIIIHHHHHH', f.read(36))

        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = fields
        
        return {
            "magic": e_ident[:4].hex(),
            "class": e_ident[4],
            "data": e_ident[5],
            "version": e_version,
            "type": e_type,
            "machine": hex(e_machine),
            "entry_point": hex(e_entry),
            "phoff": hex(e_phoff),
            "shoff": hex(e_shoff),
            "flags": hex(e_flags),
            "ehsize": e_ehsize,
            "phentsize": e_phentsize,
            "phnum": e_phnum,
            "shentsize": e_shentsize,
            "shnum": e_shnum,
            "shstrndx": e_shstrndx
        }

# Test unitario
if __name__ == "__main__":
    print("Testing header_analyzer...")
    try:
        # Solo prueba si existe un binario real
        if os.path.exists("/bin/ls"):
            result = analyze_elf_header("/bin/ls")
            print(f"ELF Header Info: {result}")
        else:
            print("No se encontró /bin/ls para testear (entorno no-Linux)")
    except Exception as e:
        print(f"Error en test: {e}")