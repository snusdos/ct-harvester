# This will run openssl to decode the data into human readable text.
# Assumes you're in project root directory  and outputs files to data/text/file.txt
echo "******Converting all .pem files to .txt...******"
for f in data/certs/*.pem;
do 
    base_filename="${f##*/}"                                        # Removes path from filename
    new_filename=${base_filename%.pem}.txt                          # Changes file ending from .pem to .txt
    openssl x509 -in "$f" -text -noout > data/text/$new_filename  # removed & Runs openssl and converts .pem to human-readable text
done
echo "******All .pem files converted to .txt.******"
