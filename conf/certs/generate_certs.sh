#!/bin/bash
# =============================================================================
# 证书生成脚本
# =============================================================================
# 生成两套独立的 CA 和证书，带正确的 EKU 限制

set -e

cd "$(dirname "$0")"

# 清理旧证书
rm -f *.crt *.key *.csr *.srl *.ext

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
  -subj "/CN=localhost/O=NeoProxy/C=CN"

cat > server.ext << 'EXT'
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1
EXT

openssl x509 -req -in server.csr -CA server-ca.crt -CAkey server-ca.key \
  -CAcreateserial -out server.crt -days 3650 -sha256 -extfile server.ext

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

# 清理临时文件
rm -f *.csr *.srl *.ext

echo ""
echo "=== 证书生成完成 ==="
echo ""
echo "证书文件:"
echo "  server-ca.crt/key  - 服务器 CA"
echo "  client-ca.crt/key  - 客户端 CA"
echo "  server.crt/key     - 服务器证书 (EKU: serverAuth)"
echo "  client.crt/key     - 客户端证书 (EKU: clientAuth)"
