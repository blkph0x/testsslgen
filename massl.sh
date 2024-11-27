#!/bin/bash

# Function to display the help message
show_help() {
  echo "Usage: $0 <options> <inputlist> or <url> or <ip address>"
  echo "  Specify either a file path containing a list of URLs, a single URL, or an IP address"
  echo "  Make sure there is no HTTP or HTTPS prefix for URLs"
  echo "  Make sure the template.docx and testssl.py files are in the same directory as this bash script"
  echo
  echo "Options:"
  echo "  -h, --help:         Display this help message and exit"
  echo "  -m, --max-scans:    Set the maximum number of concurrent scans (default: 5)"
  echo "                      Note: Too many concurrent scans will affect performance"
  echo "  -o, --output-dir:   Set the output directory for SSLyze results (default: ./SSLyzeResults)"
  echo
  echo "Example:"
  echo "  ./Massl.sh domain.txt"
  echo
  echo "Example 2: Using a single URL"
  echo "  ./Massl.sh example.com"
  echo
  echo "Example 3: Using an IP address"
  echo "  ./Massl.sh 192.168.0.1 | ./Massl.sh 192.168.0.1:8443"
  exit 0
}

# Function to handle the interrupt signal (Ctrl+C)
cleanup() {
  echo "Interrupt signal received. Stopping SSLyze..."
  # Terminate all child processes
  pkill -P $$  # Send SIGTERM to all child processes of the current script
  exit 1
}

# Register the cleanup function to handle SIGINT
trap cleanup SIGINT

# Default values if not specified on CLI
max_processes=5
output_dir="./SSLyzeResults"

# Load the Python script from the same directory as this bash script
python_script_path="$(pwd)"

# Process command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    -h|--help)
      show_help
      ;;
    -m|--max-processes)
      max_processes="$2"
      shift 2
      ;;
    -o|--output-dir)
      output_dir="$2"
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

# Check if the input is provided as an argument or show help
if [[ -z "$1" || "$1" == "--help" ]]; then
  show_help
fi

# Whatever user inputs, store it in the "input" variable
input=$1

# Make the output directory
mkdir -p "$output_dir"

# Counter for tracking the number of running processes
running_processes=0

# Function to process a domain/IP using SSLyze
process_target() {
  local target=$1

  # Process a target in the background
  sslyze --json_out=${output_dir}/${target//[:\/]/_}.json ${target} >/dev/null 2>> ./error.txt &
  echo "Scanning: ${target}"
  # Increment the running process counter
  ((running_processes++))
}

# Process the input based on its type
if [[ -f "$input" ]]; then
  # Input is a file, read URLs/IPs from the file
  mapfile -t targets < "$input"
  total="${#targets[@]}"

  # Loop through the targets and process them
  for target in "${targets[@]}"; do
    process_target "$target"

    # Check if the maximum number of processes has been reached
    if (( running_processes >= max_processes )); then
      # Wait for any background process to finish
      wait -n

      # Decrement the running process counter
      ((running_processes--))
    fi
  done
else
  # Input is a single target (URL or IP address)
  process_target "$input"
fi

# Wait for all remaining background processes to finish
wait

echo ""
echo "Finished Scanning, now generating the template"
# Now use the Python program to create a template
python "$python_script_path/testsslgen.py" ${output_dir}/*.json

# Print "Finished!" message
echo ""
echo "Finished!"
