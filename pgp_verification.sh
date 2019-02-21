wget "https://www.openssl.org/source/openssl-1.0.2q.tar.gz"
wget "https://www.openssl.org/source/openssl-1.0.2q.tar.gz.sha256"
wget "https://www.openssl.org/source/openssl-1.0.2q.tar.gz.asc"
wget -O public_key.asc "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search=0x8657ABB260F056B1E5190839D9C4D26D0E604491"

gpg2 --import public_key.asc
gpg2 --verify openssl-1.0.2q.tar.gz.asc openssl-1.0.2q.tar.gz

echo
echo "SHA-256 (expected):"
cat openssl-1.0.2q.tar.gz.sha256
echo "SHA-256 (actual):"
sha256sum openssl-1.0.2q.tar.gz
