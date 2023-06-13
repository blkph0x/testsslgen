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
  echo "  -o, --output-dir:   Set the output directory for testssl results (default: ./testSSLresults)"
  echo
  echo "Example:"
  echo "  ./Massl.sh domain.txt"
  echo
  echo "Example 2: Using a single URL"
  echo "  ./Massl.sh example.com"
  echo
  echo "Example 2: Using a single URL"
  echo "  ./Massl.sh 192.168.0.1 | ./Massl.sh 192.168.0.1:8443"
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

# Default values if not specified on CLI
max_processes=5
output_dir="./testSSLresults"

# Load the python script from the same directory as this bash script
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

# Function to process a URL
process_url() {
  local url=$1

  # Process a URL in the background
  testssl --warnings off --jsonfile-pretty ${output_dir} ${url} >/dev/null 2>> ./error.txt &
  echo "Scanning: ${url}"
  # Increment the running process counter
  ((running_processes++))
}

# Function to process an IP address
process_ip() {
  local ip_address=$1

  # Process an IP address in the background
  testssl --warnings off --jsonfile-pretty ${output_dir} ${ip_address} >/dev/null 2>> ./error.txt &
  echo "Scanning IP: ${ip_address}"
  # Increment the running process counter
  ((running_processes++))
}

# Process the input based on its type
if [[ -f "$input" ]]; then
  # Input is a file, read URLs/IPs from the file
  mapfile -t urls_ips < "$input"
  total="${#urls_ips[@]}"

  # Loop through the URLs/IPs and process them
  for url_ip in "${urls_ips[@]}"; do
    # Check if it's a URL or IP address
    if [[ $url_ip == *.* ]]; then
      process_url "$url_ip"
    else
      process_ip "$url_ip"
    fi

    # Check if the maximum number of processes has been reached
    if (( running_processes >= max_processes )); then
      # Wait for any background process to finish
      wait -n

      # Decrement the running process counter
      ((running_processes--))
    fi
  done
else
  # Input is a single URL or IP address
  if [[ $input == *.* ]]; then
    process_url "$input"
  else
    process_ip "$input"
  fi
fi

# Wait for all remaining background processes to finish
wait

echo ""
echo "Finished Scanning, now generating the template"
# Now use the python program to create a template
python "$python_script_path/testsslgen.py" ${output_dir}/*.json

# Print "Finished!" message
echo ""
echo "Finished!"
