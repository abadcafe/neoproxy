#!/bin/bash
# =============================================================================
# 证书生成脚本
# =============================================================================
# 生成两套独立的 CA 和证书，带正确的 EKU 限制

set -euo pipefail
umask 077

cd "$(dirname "$0")"
certificate_directory="$PWD"

# 全部生成成功后才替换本脚本拥有的文件；失败时保留现有证书，
# 不删除目录中其他用途的证书或私钥。
generation_directory="$(mktemp -d "$certificate_directory/.generation.XXXXXX")"
trap 'rm -rf -- "$generation_directory"' EXIT
cd "$generation_directory"

echo "=== 生成 Server CA ==="
openssl genrsa -out server-ca.key 2048
openssl req -x509 -new -nodes -key server-ca.key -sha256 -days 3650 \
  -out server-ca.crt -subj "/CN=NeoProxy-Server-CA/O=NeoProxy/C=CN"

echo "=== 生成 Client CA ==="
openssl genrsa -out client-ca.key 2048
openssl req -x509 -new -nodes -key client-ca.key -sha256 -days 3650 \
  -out client-ca.crt -subj "/CN=NeoProxy-Client-CA/O=NeoProxy/C=CN"

echo "=== 生成服务器证书 (EKU: serverAuth) ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=*.example.com/O=NeoProxy/C=CN"

cat > server.ext << 'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:*.example.com
EXT

openssl x509 -req -in server.csr -CA server-ca.crt -CAkey server-ca.key \
  -CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext

# 将 CA 证书追加到服务器证书，形成完整证书链
# 这样 TLS 握手时可以发送完整的证书链
cat server-ca.crt >> server.crt

echo "=== 生成客户端证书 (EKU: clientAuth) ==="
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr \
  -subj "/CN=client/O=NeoProxy/C=CN"

cat > client.ext << 'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EXT

openssl x509 -req -in client.csr -CA client-ca.crt -CAkey client-ca.key \
  -CAcreateserial -out client.crt -days 3650 -sha256 -extfile client.ext

for certificate_file in server-ca.key server-ca.crt client-ca.key client-ca.crt \
  server.key server.crt client.key client.crt; do
  mv -- "$certificate_file" "$certificate_directory/$certificate_file"
done

echo ""
echo "=== 证书生成完成 ==="
echo ""
echo "证书文件:"
echo "  server-ca.crt/key  - 服务器 CA"
echo "  client-ca.crt/key  - 客户端 CA"
echo "  server.crt/key     - 服务器证书 (EKU: serverAuth)"
echo "  client.crt/key     - 客户端证书 (EKU: clientAuth)"
