"""
Extracción de secciones del archivo.
"""

import struct
import os

def extract_sections(file_path, file_type):
    """
    Extrae información de las secciones de un archivo PE o ELF.
    
    Args:
        file_path (str): Ruta al archivo
        file_type (str): Tipo de archivo ("PE" o "ELF")
    
    Returns:
        list: Lista de diccionarios con información de cada sección
    """
    if file_type == "PE":
        return _extract_pe_sections(file_path)
    elif file_type == "ELF":
        return _extract_elf_sections(file_path)
    else:
        raise ValueError(f"Tipo de archivo no soportado: {file_type}")

def _extract_pe_sections(file_path):
    """Extrae secciones PE."""
    sections = []
    
    with open(file_path, 'rb') as f:
        # Saltar DOS header y leer NT header
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        
        f.seek(pe_offset)
        if f.read(4) != b'PE\x00\x00':
            raise ValueError("No es un archivo PE válido")
        
        # Número real de secciones (COFF header, offset +6)
        f.seek(pe_offset + 6)
        number_of_sections = struct.unpack('<H', f.read(2))[0]
        
        # Leer Optional Header (tamaño según magic)
        f.seek(pe_offset + 24)
        magic = struct.unpack('<H', f.read(2))[0]
        if magic == 0x10b:  # PE32
            sizeof_optional_header = 224
        elif magic == 0x20b:  # PE32+
            sizeof_optional_header = 240
        else:
            raise ValueError("Formato PE no reconocido")
        
        # Tabla de secciones: después de COFF (20 bytes) + Optional header
        section_table_offset = pe_offset + 24 + sizeof_optional_header
        f.seek(section_table_offset)
        
        for _ in range(number_of_sections):
            raw = f.read(40)
            if len(raw) < 40:
                break
            name = raw[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
            virtual_size, virtual_address = struct.unpack('<II', raw[8:16])
            size_of_raw_data, pointer_to_raw_data = struct.unpack('<II', raw[16:24])
            
            sections.append({
                'name': name,
                'virtual_size': virtual_size,
                'virtual_address': hex(virtual_address),
                'size_of_raw_data': size_of_raw_data,
                'pointer_to_raw_data': pointer_to_raw_data,
                'offset': pointer_to_raw_data,
                'size': size_of_raw_data
            })
                
    return sections

def _extract_elf_sections(file_path):
    """Extrae secciones ELF (32/64 bits, little/big endian)."""
    sections = []
    
    with open(file_path, 'rb') as f:
        e_ident = f.read(16)
        if e_ident[:4] != b'\x7fELF':
            raise ValueError("No es un archivo ELF válido")

        is_64 = e_ident[4] == 2
        endian = e_ident[5]
        fmt = '<' if endian == 1 else '>'

        if is_64:
            fields = struct.unpack(fmt + 'HHIQQQIHHHHHH', f.read(48))
        else:
            fields = struct.unpack(fmt + 'HHIIIIIHHHHHH', f.read(36))

        (_, _, _, _, _, e_shoff, _, _, _, _,
         e_shentsize, e_shnum, e_shstrndx) = fields

        # Cargar la tabla de nombres de secciones (.shstrtab)
        shstr = b''
        if e_shnum and e_shstrndx < e_shnum:
            shstr_hdr_offset = e_shoff + e_shstrndx * e_shentsize
            if is_64:
                # sh_name(4) sh_type(4) sh_flags(8) sh_addr(8) sh_offset(8) sh_size(8)
                f.seek(shstr_hdr_offset + 8 + 16)
                sh_offset, sh_size = struct.unpack(fmt + 'QQ', f.read(16))
            else:
                # sh_name(4) sh_type(4) sh_flags(4) sh_addr(4) sh_offset(4) sh_size(4)
                f.seek(shstr_hdr_offset + 8 + 8)
                sh_offset, sh_size = struct.unpack(fmt + 'II', f.read(8))
            f.seek(sh_offset)
            shstr = f.read(sh_size)

        for i in range(e_shnum):
            f.seek(e_shoff + i * e_shentsize)
            if is_64:
                sh_name, sh_type = struct.unpack(fmt + 'II', f.read(8))
                sh_flags, sh_addr, sh_offset, sh_size = struct.unpack(
                    fmt + 'QQQQ', f.read(32))
            else:
                sh_name, sh_type = struct.unpack(fmt + 'II', f.read(8))
                sh_flags, sh_addr, sh_offset, sh_size = struct.unpack(
                    fmt + 'IIII', f.read(16))

            if sh_name < len(shstr):
                name = shstr[sh_name:].split(b'\x00')[0].decode('utf-8', errors='replace')
            else:
                name = f"section_{i}"

            sections.append({
                'name': name,
                'type': sh_type,
                'flags': hex(sh_flags),
                'address': hex(sh_addr),
                'offset': sh_offset,
                'size': sh_size
            })
                
    return sections

# Test unitario
if __name__ == "__main__":
    print("Testing section_extractor...")
    try:
        if os.path.exists("/bin/ls"):
            sections = extract_sections("/bin/ls", "ELF")
            print(f"Secciones encontradas: {len(sections)}")
            for sec in sections[:3]:  # Mostrar solo las primeras tres
                print(f"  - {sec}")
        else:
            print("No se encontró /bin/ls para testear (entorno no-Linux)")
    except Exception as e:
        print(f"Error en test: {e}")