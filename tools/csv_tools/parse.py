import os
import csv
import time
from OpenSSL import crypto
from multiprocessing import Pool

#may be use https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate instead

def get_extension_value(cert, ext_name):
    extension_count = cert.get_extension_count()
    for i in range(extension_count):
        ext = cert.get_extension(i)
        if ext.get_short_name().decode() == ext_name:
            cleaned_value = str(ext).replace('\n', ' ').replace('\r', ' ').strip() #lots of newlines
            cleaned_value = ' '.join(cleaned_value.split())
            return cleaned_value
    return ""

# Load a certificate from a file and extract information
def process_certificate(cert_file):
    try:
        with open(cert_file, "rb") as file:
            cert_data = file.read()
        # Ensure the PEM start line is present
        if b"-----BEGIN CERTIFICATE-----" not in cert_data:
            print(f"Skipping invalid certificate file: {cert_file}")
            return None
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    except Exception as e:
        print(f"Error processing file {cert_file}: {e}")
        return None

    subject = cert.get_subject()
    issuer = cert.get_issuer()

    row = {
        #'serialnumber': cert.get_serial_number(),
        'serialnumber': format(cert.get_serial_number(), 'x').upper(),
        'subjectC': getattr(subject, 'C', ""),
        'subjectCN': getattr(subject, 'CN', ""),
        'subjectL': getattr(subject, 'L', ""),
        'subjectO': getattr(subject, 'O', ""),
        'subjectOU': getattr(subject, 'OU', ""),
        'issuerC': getattr(issuer, 'C', ""),
        'issuerCN': getattr(issuer, 'CN', ""),
        'issuerL': getattr(issuer, 'L', ""),
        'issuerO': getattr(issuer, 'O', ""),
        'issuerOU': getattr(issuer, 'OU', ""),
        'notBefore': cert.get_notBefore().decode(),
        'notAfter': cert.get_notAfter().decode(),
        'CRL': get_extension_value(cert, 'crlDistributionPoints'),
        'OCSP': get_extension_value(cert, 'authorityInfoAccess'),
    }
    return row

def main():
    folder_path = "" # Specify the path to your folder containing PEM files 
    #folder_path = "/Users/simonstensson/Projects/go_workspace/data/testpem"
    output_file = "" # Specify the path to your output CSV file
    
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = ['serialnumber', 'subjectC', 'subjectCN', 'subjectL', 'subjectO', 'subjectOU', 'issuerC', 'issuerCN', 'issuerL', 'issuerO', 'issuerOU', 'notBefore', 'notAfter', 'CRL', 'OCSP']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        cert_files = [os.path.join(folder_path, filename) for filename in os.listdir(folder_path) if filename.endswith(".pem")]
        
        with Pool() as pool:
            results = [result for result in pool.map(process_certificate, cert_files) if result is not None]
        
        for row in results:
            writer.writerow(row)

if __name__ == "__main__":
    start_time = time.time()

    main()

    end_time = time.time()
    execution_time = end_time - start_time
    minutes = int(execution_time // 60)
    seconds = int(execution_time % 60)
    print("Execution Time:", minutes, "minutes and", seconds, "seconds")

