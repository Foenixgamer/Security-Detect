"""
Detector de tipo de archivo basado en magic bytes.
"""

import os
import sys

def detect_file_type(file_path):
    """
    Detecta el tipo de archivo (PE, ELF, Mach-O) usando los primeros bytes.
    
    Args:
        file_path (str): Ruta al archivo
    
    Returns:
        str: Tipo de archivo detectado ("PE", "ELF", "Mach-O", o "UNKNOWN")
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Archivo no encontrado: {file_path}")
        
    with open(file_path, 'rb') as f:
        header = f.read(8)
    
    # Magic bytes para diferentes formatos
    if header[:2] == b'\x4d\x5a':  # MZ (PE)
        return "PE"
    elif header[:4] == b'\x7f\x45\x4c\x46':  # ELF
        return "ELF"
    elif header[:4] == b'\xcf\xfa\xed\xfe':  # Mach-O (Big Endian)
        return "Mach-O"
    elif header[:4] == b'\xce\xfa\xed\xfe':  # Mach-O (Little Endian)
        return "Mach-O"
    else:
        return "UNKNOWN"

# Test unitario
if __name__ == "__main__":
    print("Testing file_type_detector...")
    try:
        target = sys.executable  # El propio intérprete (PE en Windows, ELF en Linux/macOS)
        result = detect_file_type(target)
        print(f"Detectado: {result}")
    except Exception as e:
        print(f"Error en test: {e}")