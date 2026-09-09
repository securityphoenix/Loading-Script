#!/usr/bin/env python3
"""
File Extractors Module
======================

Utilities for extracting and preprocessing scanner files before parsing.
Supports ZIP, GZ, TAR, and other compressed formats.
"""

import zipfile
import gzip
import tarfile
import tempfile
import shutil
import logging
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger(__name__)


class FileExtractor:
    """Extract compressed scanner files to temporary location"""
    
    def __init__(self):
        self.temp_dirs = []
    
    def extract_if_compressed(self, file_path: str) -> str:
        """
        Extract compressed file if needed, return path to extracted file.
        If not compressed, return original path.
        """
        file_path = Path(file_path)
        
        # Check if file is compressed
        if file_path.suffix.lower() == '.zip':
            return self._extract_zip(file_path)
        elif file_path.suffix.lower() == '.gz':
            return self._extract_gz(file_path)
        elif file_path.suffix.lower() in ['.tar', '.tgz', '.tar.gz']:
            return self._extract_tar(file_path)
        else:
            # Not compressed, return as-is
            return str(file_path)
    
    def _extract_zip(self, zip_path: Path) -> str:
        """Extract ZIP file to temporary directory"""
        try:
            # Create temp directory
            temp_dir = tempfile.mkdtemp(prefix='scanner_extract_')
            self.temp_dirs.append(temp_dir)
            
            logger.info(f"Extracting ZIP: {zip_path.name} to {temp_dir}")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # Find the main file (assume first file if multiple)
            extracted_files = list(Path(temp_dir).rglob('*'))
            extracted_files = [f for f in extracted_files if f.is_file()]
            
            if not extracted_files:
                logger.warning(f"No files found in ZIP: {zip_path}")
                return str(zip_path)
            
            # Return first file (or largest if multiple)
            if len(extracted_files) == 1:
                extracted_file = extracted_files[0]
            else:
                # Return largest file
                extracted_file = max(extracted_files, key=lambda f: f.stat().st_size)
            
            logger.info(f"Extracted: {extracted_file.name} ({extracted_file.stat().st_size} bytes)")
            return str(extracted_file)
            
        except Exception as e:
            logger.error(f"Failed to extract ZIP {zip_path}: {e}")
            return str(zip_path)
    
    def _extract_gz(self, gz_path: Path) -> str:
        """Extract GZ file to temporary directory"""
        try:
            temp_dir = tempfile.mkdtemp(prefix='scanner_extract_')
            self.temp_dirs.append(temp_dir)
            
            # Output filename (remove .gz)
            output_name = gz_path.stem
            output_path = Path(temp_dir) / output_name
            
            logger.info(f"Extracting GZ: {gz_path.name} to {output_path}")
            
            with gzip.open(gz_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            logger.info(f"Extracted: {output_path.name} ({output_path.stat().st_size} bytes)")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Failed to extract GZ {gz_path}: {e}")
            return str(gz_path)
    
    def _extract_tar(self, tar_path: Path) -> str:
        """Extract TAR file to temporary directory"""
        try:
            temp_dir = tempfile.mkdtemp(prefix='scanner_extract_')
            self.temp_dirs.append(temp_dir)
            
            logger.info(f"Extracting TAR: {tar_path.name} to {temp_dir}")
            
            with tarfile.open(tar_path, 'r:*') as tar_ref:
                tar_ref.extractall(temp_dir)
            
            # Find the main file
            extracted_files = list(Path(temp_dir).rglob('*'))
            extracted_files = [f for f in extracted_files if f.is_file()]
            
            if not extracted_files:
                logger.warning(f"No files found in TAR: {tar_path}")
                return str(tar_path)
            
            # Return largest file
            extracted_file = max(extracted_files, key=lambda f: f.stat().st_size)
            
            logger.info(f"Extracted: {extracted_file.name} ({extracted_file.stat().st_size} bytes)")
            return str(extracted_file)
            
        except Exception as e:
            logger.error(f"Failed to extract TAR {tar_path}: {e}")
            return str(tar_path)
    
    def cleanup(self):
        """Clean up all temporary directories"""
        for temp_dir in self.temp_dirs:
            try:
                shutil.rmtree(temp_dir)
                logger.debug(f"Cleaned up temp dir: {temp_dir}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp dir {temp_dir}: {e}")
        
        self.temp_dirs = []
    
    def __del__(self):
        """Cleanup on destruction"""
        self.cleanup()


# Global extractor instance
_extractor = FileExtractor()


def extract_file(file_path: str) -> str:
    """
    Convenience function to extract a file if compressed.
    Returns path to extracted file (or original if not compressed).
    """
    return _extractor.extract_if_compressed(file_path)


def cleanup_extractions():
    """Cleanup all temporary extraction directories"""
    _extractor.cleanup()

