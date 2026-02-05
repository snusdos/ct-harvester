# This will remove all empty .pem files
# from data/pem/
echo "******Removing all empty .pem files...******"
find /Volumes/A1/certificates -type f -name "*.pem" -empty -exec echo "Deleting empty file: {}" \; -exec rm {} \;
echo "******All empty .pem files deleted.******"