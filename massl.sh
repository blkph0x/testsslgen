#!/bin/bash

# Function to display the help message
show_help() {
  echo "Usage: $0 <options> <input file>"
  echo "  Specify either a file path containing a list of URLs or a single URL"
  echo "  Make sure there is no HTTP or HTTPS prefix"
  echo "  Make sure the template.docx and testssl.py is in the same directory as this bash script"
  echo
  echo "Options:"
  echo "  -h, --help:         Display this help message and exit"
  echo "  -m, --max-scans:    Set the maximum number of concurrent scans (default: 5)"
  echo "                      Note: Too many concurrent scans will effect performance"
  echo "  -o, --output-dir:   Set the output directory for testssl results (default: ./testSSLresults)"
  echo
  echo "Example:"
  echo "  ./Massl.sh domain.txt"
  echo 
  echo "Example 2: Using a single URL"
  echo '  ./Massl.sh "https://example.com"'
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


# This is the default value if not specified on CLI
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


# Check if the input file is provided as an argument. -z Checking if the user input is empty or wants help
if [[ -z "$1" || "$1" == "--help" ]]; then
  show_help
fi

# Whatever user inputs, then add to variable
input=$1

# Make the output directory
mkdir -p "$output_dir"

# Finds total hosts in input file
total=$(wc -l < "$1")

# This will be used to deduct from the total variable so we know how many hosts are left
counter=0

# Find the total number of hosts
if [[ -f "$input" ]]; then
  # Input is a file, read URLs from the file
  mapfile -t urls < "$input"
  total="${#urls[@]}"
else
  # Input is a single URL
  urls=("$input")
  total=1
fi


# Counter for tracking the number of running processes
running_processes=0



# Loop through the URLs and process them
for url in "${urls[@]}"; do
  # Process a URL in the background
  testssl --warnings off --jsonfile-pretty ${output_dir} ${url} >/dev/null 2>> ./error.txt &
  echo "Scanning: ${url}" 	
  # Increment the running process counter
  ((running_processes++))
  # Increment the counter for total remaining hosts
  ((counter++))
   # Calculate how many hosts are left
   howManyLeft=$((total - counter))
   # print how many hosts are left
   echo ""
   echo "$howManyLeft hosts are remaining"	
  # Check if the maximum number of processes has been reached
  if (( running_processes >= max_processes )); then
    # Wait for any background process to finish
    wait -n

    # Decrement the running process counter
    ((running_processes--))
  fi
done


echo ""
echo "Scanning: ${url}"
# Wait for all remaining background processes to finish
wait

echo ""
echo "Finished Scanning, now generating the template"
# Now use the python program to create a template
python "$python_script_path/testsslgen.py" ${output_dir}/*.json

# Print "Finished!" message
echo ""
echo "Finished!"


