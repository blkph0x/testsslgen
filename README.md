# Install:
1. git clone https://github.com/troutman5/testsslgen.git
2. sudo pip3 install -r requirements
3. sudo apt install testssl

# Usage:
  1. ./massl.sh options input file
      - Specify the file path to the in-scope domain list
      - Make sure there is no HTTP or HTTPS prefix in the domain list.
      - Make sure the template.docx and script.py is in the same directory as this bash script.
# Example:
1. ./massl.sh listOfDomains.txt
2. cd testSSLresults
3. copy the last word file over

Options:
  1. -h, --help:         Display this help message and exit
  2. -m, --max-scans:    Set the maximum number of concurrent scans (default: 5)
      - Note: Too many concurrent scans will effect performance
  3. -o, --output-dir:   Set the output directory for testssl results (default: ./testSSLresults)

Example:
  ./Massl.sh domain.txt

# Common issues
  1. if you see err, that means the specific test didn't work. Feel free to run testssl for just that domain again. Just make sure you delete the old JSON for that domain.
      -  testssl --json-pretty domain
  2. Secure renegotation sometimes fails if cloudflare is used. Easier to use openSSL to do a quick verification.
      -  openssl s_client -no_tls1_3 -status -connect domain:port | grep -i "secure renegotiation"
3. Python script is generating three documents, i've done something weird with the loop. Will fix soon.
4. Wildcard checks not working correctly, i've done something weird with the check. Will fix soon.
  
  
