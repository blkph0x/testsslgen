# Install:
1. git clone https://github.com/troutman5/testsslgen.git
2. sudo pip3 install -r requirements
3. sudo apt install testssl

# Usage:
  ./massl.sh <options> <input file>
  Specify the file path to the in-scope domain list
  Make sure there is no HTTP or HTTPS prefix
  Make sure the template.docx and script.py is in the same directory as this bash script

Options:
  -h, --help:         Display this help message and exit
  -m, --max-scans:    Set the maximum number of concurrent scans (default: 5)
                      Note: Too many concurrent scans will effect performance
  -o, --output-dir:   Set the output directory for testssl results (default: ./testSSLresults)

Example:
  ./Massl.sh domain.txt

# Common issues
  
  
