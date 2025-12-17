"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🗜️ COMPRESSION MODULE - High-Performance Compression for Encryption       ║
║                                                                              ║
║   OPTIMIZED FOR SPEED:                                                       ║
║   - Uses 70-80% of available RAM for maximum throughput                     ║
║   - Multi-threaded compression (uses all CPU cores)                         ║
║   - Large buffer sizes for sequential I/O                                   ║
║                                                                              ║
║   Supports:                                                                  ║
║   - ZSTD (Zstandard): Best compression ratio, excellent speed               ║
║   - LZ4: Fastest compression, moderate ratio                                ║
║                                                                              ║
║   INSTALL: pip install zstandard lz4                                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import multiprocessing
from pathlib import Path
from typing import Tuple, Optional

# Compression algorithm constants
COMPRESSION_NONE = 0
COMPRESSION_ZSTD = 1
COMPRESSION_LZ4 = 2

# Check available compression libraries
try:
    import zstandard as zstd
    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

try:
    import lz4.frame
    LZ4_AVAILABLE = True
except ImportError:
    LZ4_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# MEMORY AND BUFFER CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

def get_optimal_buffer_size(target_memory_percent: float = 0.70) -> int:
    """
    Calculate optimal buffer size using 60-70% of TOTAL RAM.
    
    For a 16GB system at 70%: uses ~11.2 GB buffer
    For a 32GB system at 70%: uses ~22.4 GB buffer
    
    Args:
        target_memory_percent: Target memory usage (0.60-0.70 recommended)
    
    Returns:
        Optimal buffer size in bytes
    """
    try:
        import psutil
        total_mem = psutil.virtual_memory().total
    except ImportError:
        # Fallback: assume 8GB total
        total_mem = 8 * 1024 * 1024 * 1024
    
    # Use target percentage of TOTAL memory (no cap!)
    buffer_size = int(total_mem * target_memory_percent)
    
    # Minimum 256MB to ensure reasonable performance
    min_buffer = 256 * 1024 * 1024  # 256 MB minimum
    
    return max(min_buffer, buffer_size)


def get_thread_count() -> int:
    """Get optimal thread count for compression"""
    return multiprocessing.cpu_count()


# ═══════════════════════════════════════════════════════════════════════════
# HIGH-SPEED COMPRESSOR
# ═══════════════════════════════════════════════════════════════════════════

class Compressor:
    """
    High-performance compression for encryption pipeline.
    
    OPTIMIZED FOR SPEED:
    - Uses 70-80% of RAM for large buffers
    - Multi-threaded compression
    - Fast compression levels by default
    """
    
    @staticmethod
    def get_available_algorithms() -> list:
        """Get list of available compression algorithms"""
        algos = [("none", COMPRESSION_NONE)]
        if ZSTD_AVAILABLE:
            algos.append(("zstd", COMPRESSION_ZSTD))
        if LZ4_AVAILABLE:
            algos.append(("lz4", COMPRESSION_LZ4))
        return algos
    
    @staticmethod
    def compress(data: bytes, algorithm: int = COMPRESSION_ZSTD, 
                 level: int = 1, threads: int = None) -> Tuple[bytes, int]:
        """
        Compress data using specified algorithm.
        
        Args:
            data: Raw bytes to compress
            algorithm: Compression algorithm constant
            level: Compression level (1=fastest, higher=smaller)
            threads: Number of threads (None = auto-detect)
        
        Returns:
            (compressed_data, algorithm_used)
        """
        if algorithm == COMPRESSION_NONE:
            return data, COMPRESSION_NONE
        
        if threads is None:
            threads = get_thread_count()
        
        if algorithm == COMPRESSION_ZSTD and ZSTD_AVAILABLE:
            # Use multi-threaded compression for ZSTD
            cctx = zstd.ZstdCompressor(level=level, threads=threads)
            return cctx.compress(data), COMPRESSION_ZSTD
        
        if algorithm == COMPRESSION_LZ4 and LZ4_AVAILABLE:
            # LZ4 is already extremely fast
            return lz4.frame.compress(data, compression_level=0), COMPRESSION_LZ4
        
        return data, COMPRESSION_NONE
    
    @staticmethod
    def decompress(data: bytes, algorithm: int) -> bytes:
        """
        Decompress data using specified algorithm.
        """
        if algorithm == COMPRESSION_NONE:
            return data
        
        if algorithm == COMPRESSION_ZSTD:
            if not ZSTD_AVAILABLE:
                raise ImportError("zstandard library required")
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data)
        
        if algorithm == COMPRESSION_LZ4:
            if not LZ4_AVAILABLE:
                raise ImportError("lz4 library required")
            return lz4.frame.decompress(data)
        
        raise ValueError(f"Unknown compression algorithm: {algorithm}")
    
    @staticmethod
    def estimate_ratio(data: bytes, algorithm: int = COMPRESSION_ZSTD) -> float:
        """Estimate compression ratio for data sample."""
        sample_size = min(len(data), 65536)
        sample = data[:sample_size]
        compressed, _ = Compressor.compress(sample, algorithm, level=1)
        if len(compressed) == 0:
            return 1.0
        return len(sample) / len(compressed)
    
    @staticmethod
    def auto_select_algorithm(data: bytes) -> int:
        """Auto-select best compression algorithm."""
        if len(data) >= 4:
            magic = data[:4]
            # Skip already-compressed formats
            compressed_signatures = [
                b'PK\x03\x04', b'\x1f\x8b', b'Rar!', b'7z\xbc\xaf',
                b'\x28\xb5\x2f\xfd', b'\x89PNG', b'\xff\xd8\xff',
            ]
            for sig in compressed_signatures:
                if data.startswith(sig):
                    return COMPRESSION_NONE
        
        # Prefer LZ4 for speed, ZSTD for ratio
        if LZ4_AVAILABLE:
            return COMPRESSION_LZ4
        if ZSTD_AVAILABLE:
            return COMPRESSION_ZSTD
        return COMPRESSION_NONE


# ═══════════════════════════════════════════════════════════════════════════
# HIGH-SPEED STREAM COMPRESSOR (Uses 70-80% RAM)
# ═══════════════════════════════════════════════════════════════════════════

class StreamCompressor:
    """
    Ultra-fast streaming compression using maximum memory.
    
    SPEED OPTIMIZATIONS:
    - Uses 70-80% of available RAM for buffering
    - Multi-threaded compression (all CPU cores)
    - Single-pass I/O with huge buffers
    - Level 1 compression (fastest)
    """
    
    def __init__(self, algorithm: int = COMPRESSION_ZSTD, 
                 level: int = 1,
                 memory_percent: float = 0.75):
        """
        Initialize high-speed stream compressor.
        
        Args:
            algorithm: Compression algorithm
            level: Compression level (1 = fastest)
            memory_percent: RAM usage target (0.70-0.80 recommended)
        """
        self.algorithm = algorithm
        self.level = level
        self.memory_percent = memory_percent
        self.threads = get_thread_count()
        self.buffer_size = get_optimal_buffer_size(memory_percent)
    
    def compress_stream(self, input_path: Path, output_path: Path, 
                       progress_callback=None) -> Tuple[int, int]:
        """
        Compress file at maximum speed using 70-80% RAM.
        
        Returns (original_size, compressed_size)
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        original_size = input_path.stat().st_size
        
        if self.algorithm == COMPRESSION_NONE:
            import shutil
            shutil.copy2(input_path, output_path)
            return original_size, original_size
        
        # Use huge buffer for maximum speed
        chunk_size = min(self.buffer_size, original_size + 1)
        
        if self.algorithm == COMPRESSION_ZSTD and ZSTD_AVAILABLE:
            # Multi-threaded ZSTD with maximum speed settings
            cctx = zstd.ZstdCompressor(
                level=self.level,
                threads=self.threads,
                write_content_size=True,
                write_checksum=False  # Skip checksum for speed
            )
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # Use chunked writer for huge files
                with cctx.stream_writer(fout, size=original_size) as compressor:
                    bytes_read = 0
                    while True:
                        chunk = fin.read(chunk_size)
                        if not chunk:
                            break
                        compressor.write(chunk)
                        bytes_read += len(chunk)
                        if progress_callback:
                            pct = int((bytes_read / original_size) * 100)
                            speed = bytes_read / 1024 / 1024  # MB
                            progress_callback(pct, bytes_read, original_size, 0, 
                                            f"Compressing... {speed:.1f} MB processed")
            
            compressed_size = output_path.stat().st_size
            return original_size, compressed_size
        
        if self.algorithm == COMPRESSION_LZ4 and LZ4_AVAILABLE:
            # LZ4 is the fastest - use level 0 for maximum speed
            with open(input_path, 'rb') as fin:
                with lz4.frame.open(output_path, 'wb', 
                                   compression_level=0,  # Fastest
                                   block_size=lz4.frame.BLOCKSIZE_MAX4MB) as fout:
                    bytes_read = 0
                    while True:
                        chunk = fin.read(chunk_size)
                        if not chunk:
                            break
                        fout.write(chunk)
                        bytes_read += len(chunk)
                        if progress_callback:
                            pct = int((bytes_read / original_size) * 100)
                            progress_callback(pct, bytes_read, original_size, 0, "Compressing...")
            
            compressed_size = output_path.stat().st_size
            return original_size, compressed_size
        
        raise ValueError(f"Compression algorithm {self.algorithm} not available")
    
    def decompress_stream(self, input_path: Path, output_path: Path,
                         progress_callback=None) -> int:
        """
        Decompress file at maximum speed.
        
        Returns decompressed size
        """
        input_path = Path(input_path)
        output_path = Path(output_path)
        compressed_size = input_path.stat().st_size
        
        chunk_size = self.buffer_size
        
        if self.algorithm == COMPRESSION_NONE:
            import shutil
            shutil.copy2(input_path, output_path)
            return compressed_size
        
        if self.algorithm == COMPRESSION_ZSTD and ZSTD_AVAILABLE:
            dctx = zstd.ZstdDecompressor()
            decompressed_size = 0
            
            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                with dctx.stream_reader(fin) as reader:
                    while True:
                        chunk = reader.read(chunk_size)
                        if not chunk:
                            break
                        fout.write(chunk)
                        decompressed_size += len(chunk)
                        if progress_callback:
                            progress_callback(0, decompressed_size, 0, 0, "Decompressing...")
            return decompressed_size
        
        if self.algorithm == COMPRESSION_LZ4 and LZ4_AVAILABLE:
            decompressed_size = 0
            with lz4.frame.open(input_path, 'rb') as fin:
                with open(output_path, 'wb') as fout:
                    while True:
                        chunk = fin.read(chunk_size)
                        if not chunk:
                            break
                        fout.write(chunk)
                        decompressed_size += len(chunk)
                        if progress_callback:
                            progress_callback(0, decompressed_size, 0, 0, "Decompressing...")
            return decompressed_size
        
        raise ValueError(f"Decompression algorithm {self.algorithm} not available")


# ═══════════════════════════════════════════════════════════════════════════
# QUICK FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def compress(data: bytes, algorithm: int = COMPRESSION_ZSTD) -> Tuple[bytes, int]:
    """Quick compress with maximum speed (level 1, multi-threaded)"""
    return Compressor.compress(data, algorithm, level=1)

def decompress(data: bytes, algorithm: int) -> bytes:
    """Quick decompress"""
    return Compressor.decompress(data, algorithm)

def compress_file_fast(input_path: Path, output_path: Path, 
                      algorithm: int = COMPRESSION_LZ4,
                      progress_callback=None) -> Tuple[int, int]:
    """
    Compress file at MAXIMUM speed using 75% of RAM.
    
    Uses LZ4 by default (fastest algorithm).
    """
    compressor = StreamCompressor(algorithm=algorithm, level=1, memory_percent=0.75)
    return compressor.compress_stream(input_path, output_path, progress_callback)

def get_algorithm_name(algorithm: int) -> str:
    """Get human-readable algorithm name"""
    names = {
        COMPRESSION_NONE: "None",
        COMPRESSION_ZSTD: "ZSTD (Fast Multi-threaded)",
        COMPRESSION_LZ4: "LZ4 (Ultra-Fast)"
    }
    return names.get(algorithm, "Unknown")

def get_system_info() -> dict:
    """Get system info for compression optimization"""
    info = {
        'threads': get_thread_count(),
        'buffer_size': get_optimal_buffer_size(),
        'buffer_size_mb': get_optimal_buffer_size() / (1024 * 1024),
    }
    try:
        import psutil
        mem = psutil.virtual_memory()
        info['total_ram_gb'] = mem.total / (1024**3)
        info['available_ram_gb'] = mem.available / (1024**3)
    except ImportError:
        info['total_ram_gb'] = 'unknown'
        info['available_ram_gb'] = 'unknown'
    return info

