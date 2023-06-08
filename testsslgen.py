import json #to handle JSON
import sys #to handle data parse from terminal argument
import pandas as pd # handle dataframe for docx table output

#pip install python-docx
import docx # for ms word docx
from docxtpl import DocxTemplate  
import time # for timedate string on file output
import re # regex for url verification

from docx.oxml.ns import nsdecls
from docx.oxml import parse_xml



def testProtocolVersions(protocolResult):

    # defines a dictionary to store each result
    hostFindings = {
        'SSLv2': '',
        'SSLv3': '',
        'TLS1': '',
        'TLS1_1': '',
        'TLS1_2': '',
        'TLS1_3': '',
    }

    for i in range(len(protocolResult)): # iterates through every protocol test done (ie each host)


        #defines an offering
        def offernotoffer(finding):
            if 'not' in finding:
                return 'No'
            else: 
                return 'Yes'




        protocolId = protocolResult[i]['id']
        finding = protocolResult[i]['finding']


        #seeks a protocol test and then updates it based off finding 
        if protocolId == 'SSLv2':
            hostFindings.update(SSLv2 = offernotoffer(finding))
        elif protocolId == 'SSLv3':
            hostFindings.update(SSLv3 = offernotoffer(finding))
        elif protocolId == 'TLS1':
            hostFindings.update(TLS1 = offernotoffer(finding))
        elif protocolId == 'TLS1_1':
            hostFindings.update(TLS1_1 = offernotoffer(finding))

        ## special case for TLS1_2
        elif protocolId == 'TLS1_2':

            #if TLS1_2 and not offered
            if "not" in finding:
                hostFindings.update(TLS1_2 = 'no / maybe')
                
                for j in range(len(protocolResult)):
                    if protocolResult[j]['id'] == 'TLS1_3':

                        #If TLS1_3 not offered --> no
                        if 'not' in protocolResult[j]['finding']:
                            hostFindings.update(TLS1_2 = 'No') 


                        #If TLS1_3 is offered --> no + tls13 result
                        else: 
                            hostFindings.update(TLS1_2 = 'No (with TLS1.3 Support)') 

                
            else:
                hostFindings.update(TLS1_2 = 'Yes')
        #back to normal here
        elif protocolId == 'TLS1_3':
            hostFindings.update(TLS1_3 = offernotoffer(finding))
    

    return hostFindings #returns dictionary to higher function

def testCipherSuite(cipherResult):

    cipherFindings = {
        'NullCiphers': '',
        'AnonCiphers': '',
        'RC4Ciphers': '',
        'TripleDes': '',
        'CBC_Ciphers': '',
    }


    for i in range(len(cipherResult)):

        cipherId = cipherResult[i]['id']
        finding = cipherResult[i]['finding']

        #defines an offering
        def offernotoffer(finding):
            if 'not' in finding:
                return 'No'
            else: 
                return 'Yes'

        # defines a dictionary to store each result


        #seeks a cipher test and then updates it based off finding 
        if cipherId == 'cipherlist_NULL':
            cipherFindings.update(NullCiphers = offernotoffer(finding))
        elif cipherId == 'cipherlist_aNULL':
            cipherFindings.update(AnonCiphers = offernotoffer(finding))
        elif cipherId == 'cipherlist_LOW':
            cipherFindings.update(RC4Ciphers = offernotoffer(finding))
        elif cipherId == 'cipherlist_3DES_IDEA':
            cipherFindings.update(TripleDes = offernotoffer(finding))
        elif cipherId == 'cipherlist_AVERAGE':
            cipherFindings.update(CBC_Ciphers = offernotoffer(finding))

    return cipherFindings

def testMisconfig(vulnerabiltiesResult, pfsResult):

    misconfigFindings = {
        'clientRenegotiation': '',
        'secureRenegotiation': '',
        'TLSFallback': '',
        'PerfectForwardSec': '',
    }


    for i in range(len(vulnerabiltiesResult)):

        vulnerabiltyID = vulnerabiltiesResult[i]['id']
        finding = vulnerabiltiesResult[i]['finding']

        #seeks a cipher test and then updates it based off finding 
        if vulnerabiltyID == 'secure_client_renego':
            if finding == 'vulnerable':
                misconfigFindings.update(clientRenegotiation = 'Yes')
            elif finding == "OpenSSL handshake didn't succeed":
                misconfigFindings.update(clientRenegotiation = 'ERR')
            else:
                misconfigFindings.update(clientRenegotiation = 'No')

        elif vulnerabiltyID == 'secure_renego':
            if finding == 'not vulnerable':
                misconfigFindings.update(secureRenegotiation = 'No')
            elif finding == "OpenSSL handshake didn't succeed":
                misconfigFindings.update(secureRenegotiation = 'ERR')
            else:
                misconfigFindings.update(secureRenegotiation = 'Yes')

        elif vulnerabiltyID == 'fallback_SCSV':
            if finding == 'supported' or finding == 'no protocol below TLS 1.2 offered':
                misconfigFindings.update(TLSFallback = 'Yes')
            elif finding == "OpenSSL handshake didn't succeed":
                misconfigFindings.update(TLSFallback = 'ERR')
            else:
                misconfigFindings.update(TLSFallback = 'No')

    for j in range(len(pfsResult)):
        pfsID = pfsResult[j]['id']
        finding = pfsResult[j]['finding']

        if pfsID == 'PFS':
            if finding == 'offered':
                misconfigFindings.update(PerfectForwardSec = 'Yes')
            elif '--' in finding: 
                misconfigFindings.update(PerfectForwardSec = 'Err')
            else:
                misconfigFindings.update(PerfectForwardSec = 'No')


    return misconfigFindings

def testCertificateIssues(certificateResults, hostname):

    #to convert a wildcard url for purpose of matching
    #python doesnt like matching '*.example.com' to 'example.com'
    #what this function does it retrieve all url's on server (certificateURLs) and replaced the '*.' with a blank string, it stores all the arrays retrieved from certificate as array
    #then it iterates through the array trying to match any part of the certificate url to the hostname, if it does this it returns true
    #if it runs through all urls and there is no match, it returns false

    def wildcardURL_isMatch(certificateURLs, hostname):

        # if hostname is abc.example.com and certurl is *.example.com -- YES
        # if hostname is abc.coalservices.com and certurl is abc.example.com -- NO
        # else -- N/A
        certificateURL_array = certificateURLs.split(' ')
        
        #testCertURL = ['azure.com', 'b']
        #testHost = 'rds.coalservices.com.au'

        # way algorithm works:
        # checks if hostname is in exactly in cert_subjectAltName and there is no hostname with wild (as in *.example.com), if match, return 'no'
        # if not match, test to see if host in cert_subjectAltName with *. removed (ie if example.com is in *.example.com), if match return yes
        # if else, return N/A

        hostnamewithwild = '*.' + hostname

        if hostname in certificateURL_array and hostnamewithwild not in certificateURL_array:
            #print(' NO: ' + hostname + ', cert urls: '+ str(certificateURL_array))
            return 'No'
        else:
            for url in certificateURL_array: 
                #print(url.replace('*.', ''))
                if url.replace('*.', '') in hostname: 
                    #print(' Yes: ' + hostname + ', cert urls: '+ str(certificateURL_array))
                    return 'Yes'
        
        return 'N/A'
        print(' N/A: ' + hostname + ', cert urls: '+ str(certificateURL_array))

    certificateFindings = {
        'Wildcard': '',
        'CRL': '',
        'OCSP': '',
        'OCSP_Stapled': '',
        'CAA': '',
    }

    

    for i in range(len(certificateResults)):

        certificateId = certificateResults[i]['id']
        finding = certificateResults[i]['finding']

        if 'cert_subjectAltName' in certificateId:
            #see function documentation
            certificateFindings.update(Wildcard = wildcardURL_isMatch(finding, hostname))

        elif 'cert_crlDistributionPoints' in certificateId:
            #uses regex to determine if theres a url 
            #regex taken from https://uibakery.io/regex-library/url-regex-python
            url_pattern = "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$"

            #once again iterates through the multiple urls in the json
            for element in finding.split():
                if re.match(url_pattern, element): 
                    #print('true')
                    certificateFindings.update(CRL = 'No')

                certificateFindings.update(CRL = 'Yes')

        elif 'OCSP_stapling' in certificateId:
            if finding == 'not offered':
                certificateFindings.update(OCSP = 'No')
            elif finding == 'offered':
                certificateFindings.update(OCSP = 'Yes')
            else: 
                certificateFindings.update(OCSP = 'err')
        elif 'mustStapleExtension' in certificateId or str(certificateId) == 'cert_mustStapleExtension':
            if '--' in str(finding):
                certificateFindings.update(OCSP_Stapled = 'No')
            else:
                certificateFindings.update(OCSP_Stapled = 'Yes')
        elif 'DNS_CAArecord' in certificateId:
            if '--' in str(finding):
                certificateFindings.update(CAA = 'No')
            else:
                certificateFindings.update(CAA = 'YesYes2')
    return certificateFindings

# Read multiple JSON files passed as command line arguments
json_files = sys.argv[1:]

protocolDictionary = {}
cipherDictionary = {}
misconfigDictionary = {}
certificateDictionary = {}

# Process each JSON file
for file in json_files:
    with open(file) as json_data:
        argumentData = json.load(json_data)
        scanResult = argumentData['scanResult']


    #iterates through each host
    for j in range(len(scanResult)):

        if 'targetHost' in scanResult[j]: ## checks that the dictionary it is about to read is an actual result not something else

            #defines the host by hostname (targetHost) and ip
            host = scanResult[j]['targetHost'] + '\n' + scanResult[j]['ip']
            hostip = scanResult[j]['ip']
            hostname = scanResult[j]['targetHost']


            # ~~~ PROTOCOL TESTING ~~~
            #calls the 'testProtocols', then sorts results into array for addition to dictionary 
            hostProtcolDictionary = testProtocolVersions(scanResult[j]['protocols'])
            hostProtocolArray = [
                    host,
                    hostProtcolDictionary['SSLv2'],
                    hostProtcolDictionary['SSLv3'],
                    hostProtcolDictionary['TLS1'],
                    hostProtcolDictionary['TLS1_1'],
                    hostProtcolDictionary['TLS1_2'],
                    hostProtcolDictionary['TLS1_3']
                ]

            protocolDictionary.update({host: hostProtocolArray})            


            # ~~~ CIPHER TESTING ~~~
            hostCipherDictionary = testCipherSuite(scanResult[j]['ciphers'])
            hostCipherArray = [
                    host,
                    hostCipherDictionary['NullCiphers'],
                    hostCipherDictionary['AnonCiphers'],
                    hostCipherDictionary['RC4Ciphers'],
                    hostCipherDictionary['TripleDes'],
                    hostCipherDictionary['CBC_Ciphers'],
                ]
            cipherDictionary.update({host: hostCipherArray})            

            # ~~~ MISCONFIGURE TESTING ~~~
            hostMisconfigDictionary = testMisconfig(scanResult[j]['vulnerabilities'], scanResult[j]['pfs']) 
            hostMisconfigArray = [
                    host,
                    hostMisconfigDictionary['clientRenegotiation'],
                    hostMisconfigDictionary['secureRenegotiation'],
                    hostMisconfigDictionary['TLSFallback'],
                    hostMisconfigDictionary['PerfectForwardSec'],
                ]

            misconfigDictionary.update({host: hostMisconfigArray})            

            # ~~~ CERTIFICATE TESTING ~~~ 
            hostCertificateDictionary = testCertificateIssues(scanResult[j]['serverDefaults'], hostname)

            hostCertificateArray = [
                    host,
                    hostCertificateDictionary['Wildcard'],
                    hostCertificateDictionary['CRL'],
                    hostCertificateDictionary['OCSP'],
                    hostCertificateDictionary['OCSP_Stapled'],
                    hostCertificateDictionary['CAA'],
                ]

            certificateDictionary.update({host: hostCertificateArray})            

            

        #PROTOCOL - Dataframing
        protocolDataFrame_untransposed = pd.DataFrame(protocolDictionary)
        protocolDataFrame = protocolDataFrame_untransposed.T
        protocolDataFrame.columns = ['Host', 'SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3']
        protocolDataFrame = protocolDataFrame.set_index('Host')

        #CIPHER -- Dataframing

        cipherDataFrame_untransposed = pd.DataFrame(cipherDictionary)
        cipherDataFrame = cipherDataFrame_untransposed.T
        cipherDataFrame.columns = ['Host', 'NullCiphers', 'AnonCiphers', 'RC4Ciphers', 'TripleDES', 'CBCCiphers']
        cipherDataFrame = cipherDataFrame.set_index('Host')


        #MISCONFIGURATION -- Dataframing
        misconfigDataFrame_untransposed = pd.DataFrame(misconfigDictionary)
        misconfigDataFrame = misconfigDataFrame_untransposed.T
        misconfigDataFrame.columns = ['Host', 'ClientReneg', 'SecureReneg', 'TLSFallback', 'PFS']
        misconfigDataFrame = misconfigDataFrame.set_index('Host')


        #CERTIFICATE ISSUES -- Dataframing
        certificateDataframe_untransposed = pd.DataFrame(certificateDictionary)
        certificateDataframe = certificateDataframe_untransposed.T
        certificateDataframe.columns = ['Host', 'Wildcard', 'CRL', 'OCSP', 'OCSPstaple', 'CAA']
        certificateDataframe = certificateDataframe.set_index('Host')


    #~~ debugging~
    #print(protocolDataFrame)
    #print(certificateDataframe)
    #print(cipherDataFrame)
    #print(misconfigDataFrame)
    

    #sets a dictionary up with all the labels for the tables
    context = {
        'pro_col_labels': ['SSLv2', 'SSLv3', 'TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'],
        'pro_tbl_contents': [],
        'cip_col_labels': ['Null Ciphers', 'Anonymous Ciphers', 'RC4 Ciphers', 'Triple DES', 'CBC ciphers'],
        'cip_tbl_contents' :[],
        'mis_col_labels': ['Client-initiated renegotiation is supported', 'Secure renegotiation is supported', 'TLS Fallback SCSV supported', 'Perfect Forward Secrecy (PFS) '],
        'mis_tbl_contents' :[],
        'cert_col_labels': ['Wildcard or Shared Certificates', 'CRL enabled', 'OCSP enabled', 'OCSP must staple enabled', 'CAA record defined'],
        'cert_tbl_contents': []
    }


    #parses dataframe to dictionary for python docx tpl use
    for item in protocolDataFrame.to_dict('index').items():
        newDict = {
            'label': [],
            'cols': []
        }
        newDict['label'] = item[0] 
        newDict['cols'] = [item[1]['SSLv2'], item[1]['SSLv3'], item[1]['TLS 1.0'], item[1]['TLS 1.1'], item[1]['TLS 1.2'], item[1]['TLS 1.3']]
        context['pro_tbl_contents'].append(newDict)

    for item in cipherDataFrame.to_dict('index').items():
        newDict = {
            'label': [],
            'cols': []
        }
        newDict['label'] = item[0] 
        newDict['cols'] = [item[1]['NullCiphers'], item[1]['AnonCiphers'], item[1]['RC4Ciphers'], item[1]['TripleDES'], item[1]['CBCCiphers']]
        context['cip_tbl_contents'].append(newDict)

    for item in misconfigDataFrame.to_dict('index').items():
        newDict = {
            'label': [],
            'cols': []
        }
        newDict['label'] = item[0] 
        newDict['cols'] = [item[1]['ClientReneg'], item[1]['SecureReneg'], item[1]['TLSFallback'], item[1]['PFS']]
        context['mis_tbl_contents'].append(newDict)

    for item in certificateDataframe.to_dict('index').items():
        newDict = {
            'label': [],
            'cols': []
        }
        newDict['label'] = item[0] 
        newDict['cols'] = [item[1]['Wildcard'], item[1]['CRL'], item[1]['OCSP'], item[1]['OCSPstaple'], item[1]['CAA']]
        context['cert_tbl_contents'].append(newDict)



    #grabs template 
    tpl = DocxTemplate('template.docx')
    tpl.render(context)

    dateTime = time.strftime("%Y%m%d-%H%M%S")


    #formatting

    def set_colour(cell, colour):
        #python-docx and python-docx-tpl has poor formatting, this changes the XML in the actual docx file for us
        #the HEX codes are put as comment for your use. You can change it in the w:fill variable within the code
        if colour == 'green':
            #90ee90'
            shading_elm = parse_xml(r'<w:shd {} w:fill="90ee90"/>'.format(nsdecls('w')))
            cell._tc.get_or_add_tcPr().append(shading_elm)
        elif colour == 'red':
            #'FF7276'
            shading_elm = parse_xml(r'<w:shd {} w:fill="FF7276"/>'.format(nsdecls('w')))
            cell._tc.get_or_add_tcPr().append(shading_elm)
        elif colour == 'orange':
            #'FF7276'
            shading_elm = parse_xml(r'<w:shd {} w:fill="ff9248"/>'.format(nsdecls('w')))
            cell._tc.get_or_add_tcPr().append(shading_elm)
        else: 
            return


    #python-docx and python-docx-template doesnt have conditional formatting
    #this iterates every table, then every column, then every cell in that column and conditionally colours it 
    for table in tpl.tables:
        for table_column in table.columns:

            column_heading = table_column.cells[0].text

            ##Certificate Issues
            if column_heading == 'Wildcard or Shared Certificates':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'CRL enabled':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')
            elif column_heading == 'OCSP enabled':
                for cell in table_column.cells:
                    if cell.text == 'No':
                        set_colour(cell, 'orange')
                    elif cell.text =='Yes':
                        set_colour(cell, 'green')
            elif column_heading == 'OCSP must staple enabled':
                for cell in table_column.cells:
                    if cell.text == 'No':
                        set_colour(cell, 'orange')
                    elif cell.text =='Yes':
                        set_colour(cell, 'green')
            elif column_heading == 'CAA record defined':
                for cell in table_column.cells:
                    if cell.text == 'No':
                        set_colour(cell, 'orange')
                    elif cell.text =='Yes':
                        set_colour(cell, 'green')
            ##Protocol Issues
            elif column_heading == 'SSLv2':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'SSLv3':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'TLS 1.0':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'TLS 1.1':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'TLS 1.2':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')
                    elif cell.text =='No (with TLS1.3 Support)':
                        set_colour(cell, 'green')


                        #Little loop to match job description
                        for p in cell.paragraphs:
                            if "No (with TLS1.3 Support)" in p.text:
                                inline = p.runs
                                # Loop added to work with runs (strings with same style)
                                for i in range(len(inline)):
                                    if "No (with TLS1.3 Support)" in inline[i].text:
                                        text = inline[i].text.replace("No (with TLS1.3 Support)", 'No')
                                        inline[i].text = text
            elif column_heading == 'TLS 1.3':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')

            ##Cipher Suite Issues 
            elif column_heading == 'Null Ciphers':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'Anonymous Ciphers':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'RC4 Ciphers':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'Triple DES':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'CBC ciphers':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')


            ##Misconfiguration Issues
            elif column_heading == 'Client-initiated renegotiation is supported':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'orange')
                    elif cell.text =='No':
                        set_colour(cell, 'green')
            elif column_heading == 'Secure renegotiation is supported':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')
            elif column_heading == 'TLS Fallback SCSV supported':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')
            elif column_heading == 'Perfect Forward Secrecy (PFS) ':
                for cell in table_column.cells:
                    if cell.text == 'Yes':
                        set_colour(cell, 'green')
                    elif cell.text =='No':
                        set_colour(cell, 'orange')

  
    #saves document
    tpl.save(sys.argv[1] + ' - ' + dateTime + '.docx')
