"""
Colección de metadatos del archivo.
"""

import os
import sys
import time

def collect_metadata(file_path):
    """
    Recopila información básica del archivo.
    
    Args:
        file_path (str): Ruta al archivo
    
    Returns:
        dict: Diccionario con los metadatos
    """
    stat_info = os.stat(file_path)
    
    return {
        "file_path": file_path,
        "size_bytes": stat_info.st_size,
        "created_time": time.ctime(stat_info.st_ctime),
        "modified_time": time.ctime(stat_info.st_mtime),
        "accessed_time": time.ctime(stat_info.st_atime),
        "permissions": oct(stat_info.st_mode)[-3:],
        "is_executable": bool(stat_info.st_mode & 0o111)
    }

# Test unitario
if __name__ == "__main__":
    print("Testing metadata_collector...")
    try:
        target = sys.executable
        result = collect_metadata(target)
        print(f"Metadata collected: {result}")
    except Exception as e:
        print(f"Error en test: {e}")