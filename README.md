# Install:
1. git clone https://github.com/troutman5/testsslgen.git
2. cd testsslgen
3. chmod +x testsslgen.py
4. chmod +x massl.sh
5. sudo pip3 install -r requirements
6. sudo apt install testssl


# Usage:
  1. ./massl.sh options input_file | url | ip
      - Specify either a file path containing a list of URLs or a single URL
      - Make sure there is no HTTP or HTTPS prefix in the domain list.
      - Make sure the template.docx and script.py is in the same directory as this bash script.
Options:
  1. -h, --help:         Display this help message and exit
  2. -m, --max-scans:    Set the maximum number of concurrent scans (default: 5)
      - Note: Too many concurrent scans will effect performance
  3. -o, --output-dir:   Set the output directory for testssl results (default: ./testSSLresults)


# Example:
1. ./massl.sh listOfDomains.txt | ./massl.sh domain.com | ./massl.sh 192.168.0.1 | ./massl.sh -o domainResults google.com 
2. cd testSSLresults or whatever directory you specified with -o
3. copy the last word file over to host. (at the moment it makes 3, will fix that soon)


# Common issues
  1. if you see err, that means the specific test didn't work. Feel free to run testssl for just that domain again. Just make sure you delete the old JSON for that domain.
      -  testssl --json-pretty domain
  2. Secure renegotation sometimes fails if cloudflare is used. Easier to use openSSL to do a quick verification.
      -  openssl s_client -no_tls1_3 -status -connect domain:port | grep -i "secure renegotiation"
3. Python script is generating three documents, i've done something weird with the loop. Will fix soon.
  
  
