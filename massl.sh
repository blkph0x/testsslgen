#!/bin/bash

# Function to display the help message
show_help() {
  echo "Usage: $0 <input_file | url | ip_range>"
  echo "  Specify either a file path containing a list of URLs, a single URL, or an IP range"
  echo "  If providing a file, make sure there is no HTTP or HTTPS prefix in the URLs"
  echo
  echo "Options:"
  echo "  -h, --help:         Display this help message and exit"
  echo "  -m, --max-processes:  Set the maximum number of concurrent scans (default: 5)"
  echo "                      Note: Too many concurrent scans will affect performance"
  echo "  -o, --output-dir:   Set the output directory for testssl results (default: ./results)"
  echo
  echo "Example 1: Using a file containing URLs"
  echo "  ./Massl.sh domain.txt"
  echo
  echo "Example 2: Using a single URL"
  echo '  ./Massl.sh "https://example.com"'
  echo
  echo "Example 3: Using an IP range"
  echo '  ./Massl.sh 192.168.0.1/24'
  exit 0
}

# Function to handle the interrupt signal (Ctrl+C)
cleanup() {
  echo "Interrupt signal received. Stopping testssl..."
  # Terminate all child processes
  pkill -P $$  # Send SIGTERM to all child processes of the current script
  exit 1
}

# Register the cleanup function to handle SIGINT
trap cleanup SIGINT

# Default values
max_processes=5
output_dir="./testSSLresults"
# Load the python script wherever this bash script is
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

# Check if the input is provided as an argument or user requested help
if [[ -z "$1" || "$1" == "--help" ]]; then
  show_help
fi

input=$1

# Create the output directory if it doesn't exist
mkdir -p "$output_dir"

# Check if the input is an IP range
if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
  # Split the IP range into IP address and subnet
  ip="${input%/*}"
  subnet="${input#*/}"

  # Calculate the number of IP addresses in the subnet
  num_addresses=$((2 ** (32 - subnet)))

  # Convert the IP address to a 32-bit integer
  IFS='.' read -r -a ip_parts <<< "$ip"
  ip_int=$(( (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3] ))

  # Generate the list of IP addresses
  echo "Generating List of IPs"
  ips=()
  for ((i = 0; i < num_addresses; i++)); do
    # Convert the 32-bit integer back to IP address
    ip_address="$(( (ip_int & 0xFF000000) >> 24 )).$(( (ip_int & 0x00FF0000) >> 16 )).$(( (ip_int & 0x0000FF00) >> 8 )).$(( ip_int & 0x000000FF ))"
    ips+=("$ip_address")

    # Increment the IP address for the next iteration
    ((ip_int++))
  done
else
  # Read the input file or treat the input as a single URL
  if [[ -f "$input" ]]; then
    # Input is a file
    urls_file="$input"
    
  else
    # Input is a single URL
    urls=("$input")
  fi
fi

# Function to process a URL
process_url() {
  local url=$1

  # Process a URL in the background
  testssl --warnings off --json-pretty "$url" >/dev/null 2>> "$output_dir/error.txt"

  # Print the scanned URL
  #echo "Scanning: $url"
}

# Function to process an IP address
process_ip() {
  local ip_address=$1

  # Process an IP address in the background
  testssl --warnings off --json-pretty "$ip_address" >/dev/null 2>> "$output_dir/error.txt"

  # Print the scanned IP address
  echo "Scanning IP: $ip_address"
}

# Counter for tracking the number of running processes
running_processes=0

# to determine how many hosts left in the list
counter=0

# Loop through the URLs or IP addresses and process them
if [[ -n "${urls_file}" ]]; then
  # Read URLs from a file
  while IFS= read -r url; do
      # Wait until the number of running processes is less than the maximum
    while ((running_processes >= max_processes)); do
      sleep 1
    done

    process_url "$url" &
    echo "Scanning $url"
    ((running_processes++))
  done < "$urls_file"
elif [[ ${#ips[@]} -gt 0 ]]; then
  # Process IP addresses
  for ip_address in "${ips[@]}"; do
    # Wait until the number of running processes is less than the maximum
    while ((running_processes >= max_processes)); do
      sleep 1
    done

    process_ip "$ip_address" &
    echo "scannin: $ip_address"
    ((running_processes++))
  done
else
  # Process a single URL
  process_url "$input" &
  ((running_processes++))
fi

echo "Scanning: $input"

# Wait for all remaining background processes to finish
wait

# Call the Python script with the output directory as an argument
python "$python_script_path/testsslgen.py" ${output_dir}/*.json

# Print "Finished!" message
echo "Finished!"
