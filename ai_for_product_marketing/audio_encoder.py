#!/usr/bin/python3

from pathlib import Path
import sys
import subprocess
import logging
from datetime import datetime
import argparse

def set_up_logging(output_dir):
    """Configure logging with proper formatting and level."""
    # Create log filename with timestamp
    timestamp = datetime.now().strftime('%Y-%m-%d-%H:%M')
    log_file = Path(output_dir) / f"{timestamp}-encoding.log"
    
    # Create formatters
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_formatter = logging.Formatter('%(message)s')
    
    # Set up root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    root_logger.handlers = []
    
    # File handler with timestamp format
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    # Console handler with simpler format
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    print(f"\nStarting audio conversion...")
    logging.info(f"Logging to file: {log_file}")

def get_audio_files(directory):
    """Retrieves list of convertible audio files from a directory."""
    audio_files = []
    try:
        # Convert to Path object and resolve to absolute path
        dir_path = Path(directory).resolve()
        
        # Use rglob with case-insensitive pattern matching
        audio_extensions = ('.wav', '.mp3', '.flac', '.aac', '.mp4', '.m4a', '.ogg')
        audio_files.extend(
            file for file in dir_path.iterdir()
            if file.is_file() and file.suffix.lower() in audio_extensions
        )
    
    except Exception as e:
        logging.error(f"Error reading directory {directory}: {e}")
    
    return audio_files

def check_output_conflicts(audio_files, output_dir):
    """Check for filename conflicts before starting conversion process."""
    conflicts = []
    final_output_files = {}
    
    for file_path in audio_files:
        output_file = Path(output_dir) / f"{file_path.stem}.m4a"
        if output_file.exists():
            conflicts.append((file_path, output_file))
        else:
            final_output_files[file_path] = output_file
            
    return conflicts, final_output_files

def resolve_conflicts(conflicts, output_dir):
    """Resolve filename conflicts through user interaction."""
    resolved_files = {}
    
    if conflicts:
        for input_file, output_file in conflicts:
            while True:
                response = input(f"\nFile '{output_file.name}' already exists. Overwrite file? Choose 'y' to overwrite, 'n' to give a new name, or 'q' to quit (y/n/q): ").lower().strip()
                if response == 'q':
                    print("\nExiting program...")
                    sys.exit(0)
                elif response == 'y':
                    resolved_files[input_file] = output_file
                    break
                elif response == 'n':
                    new_name = input("Enter new filename (without extension) or 'q' to quit: ").strip()
                    if new_name.lower() == 'q':
                        print("\nExiting program...")
                        sys.exit(0)
                    elif new_name:
                        resolved_files[input_file] = Path(output_dir) / f"{new_name}.m4a"
                        break
                    else:
                        print("Filename cannot be empty. Please try again.")
                else:
                    print("Please answer 'y', 'n', or 'q'.")
                    
    return resolved_files

def encode_audio(file_path, output_file):
    """Encodes an audio file to AAC format using ffmpeg."""
    try:
        # Construct ffmpeg command
        cmd = [
            "ffmpeg",
            "-y",  # Force overwrite without prompting
            "-i", str(file_path),
            "-vn",  # No video
            "-c:a", "aac",
            "-b:a", "16k",
            "-loglevel", "error",
            "-stats",
            str(output_file)
        ]

        # Run the encoding process
        print(f"\nProcessing: {file_path.name}")
        logging.info(f"Encoding '{file_path}' to AAC format...")
        result = subprocess.run(cmd, capture_output=True, text=True)

        # Check if encoding was successful
        if result.returncode == 0 and output_file.exists() and output_file.stat().st_size > 0:
            logging.info(f"Successfully encoded '{file_path}' to '{output_file}'")
            return True
        else:
            print(f"Failed to convert: {file_path.name}")
            logging.error(f"Failed to encode '{file_path}': {result.stderr}")
            return False

    except Exception as e:
        logging.error(f"Error encoding file: {str(e)}")
        return False

def get_directory_input(prompt, default=None, must_exist=False):
    """Get directory input from user with option to exit."""
    while True:
        user_input = input(prompt).strip()
        
        if user_input.lower() in ['q', 'quit', 'exit']:
            print("\nExiting program...")
            sys.exit(0)
            
        # Use default if no input and default provided
        if not user_input and default:
            path = Path(default).resolve()
        elif user_input:
            path = Path(user_input).resolve()
        else:
            print("Please enter a valid directory path or 'q' to quit")
            continue
            
        # Check if directory exists when required
        if must_exist and not path.is_dir():
            print(f"Error: Directory '{path}' does not exist")
            print("Please try again or enter 'q' to quit")
            continue
            
        return path

def main():
    """Main function to handle command-line arguments and file processing."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Audio file transcoder to AAC format')
    parser.add_argument('input_dir', nargs='?', help='Input directory containing audio files')
    parser.add_argument('output_dir', nargs='?', help='Output directory for encoded files')
    
    args = parser.parse_args()
    
    # Initialize variables
    input_dir = None
    output_dir = None
    
    # Handle directory inputs
    if args.input_dir and args.output_dir:
        input_dir = Path(args.input_dir).resolve()
        output_dir = Path(args.output_dir).resolve()
        
        # Verify input directory exists when provided via arguments
        if not input_dir.is_dir():
            print(f"Error: Input directory '{input_dir}' does not exist")
            return
    else:
        print("Usage ./audio_encoder.py <input_dir> <output_dir>. No arguments provided - entering interactive mode.")
        print("Type 'q', 'quit', or 'exit' at any prompt to exit the program.\n")
        
        # Get input directory with existence check
        input_dir = get_directory_input(
            "Enter the input directory with the files to encode (or press enter to use the current directory): ",
            Path.cwd(),
            must_exist=True
        )
        
        # Get output directory (doesn't need to exist yet)
        output_dir = get_directory_input(
            "Enter the output directory (or press enter to use the current directory): ",
            Path.cwd()
        )
    
    # Verify input directory exists
    if not input_dir.is_dir():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return
            
    # Create output directory if it doesn't exist
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get audio files from input directory
    audio_files = get_audio_files(input_dir)
    
    if not audio_files:
        print(f"Error: No audio files found in input directory '{input_dir}'")
        return
    
    # Check for filename conflicts before starting conversion
    conflicts, final_output_files = check_output_conflicts(audio_files, output_dir)
    
    # Resolve any conflicts through user interaction
    resolved_files = resolve_conflicts(conflicts, output_dir)
    
    # Merge resolved files with non-conflicting files
    final_output_files.update(resolved_files)
    
    # Set up logging now that we're ready to start conversion
    set_up_logging(output_dir)
    
    # Initialize counters
    total_files = len(audio_files)
    successfully_processed = 0
    
    # Process audio files
    logging.info(f"Found {total_files} audio file(s)")
    for input_file, output_file in final_output_files.items():
        if encode_audio(input_file, output_file):
            successfully_processed += 1
    
    # Print summary
    failed = total_files - successfully_processed
    summary = f"""
Processing Summary:
----------------
Total audio files found: {total_files}
Successfully processed:   {successfully_processed}
Failed to encode:      {failed}
"""
    logging.info(summary)

if __name__ == "__main__":
    main()
