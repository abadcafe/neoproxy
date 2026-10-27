#!/usr/bin/env bash
# Build an isolated curl with experimental HTTP/3 proxy support.
# Used by the two-hop matrix; never replaces the user's curl.
set -euo pipefail

matrix_root="$(cd "$(dirname "$0")/.." && pwd)/tmp/curl-h3"
matrix_prefix="$matrix_root/prefix"
matrix_jobs="${NEOPROXY_BUILD_JOBS:-4}"
mkdir -p "$matrix_root/source"

fetch_source() {
  local name="$1" version="$2" url="$3" checksum="$4"
  local archive="$matrix_root/source/$name.tar.gz"
  if [[ ! -f "$archive" ]]; then
    curl --fail --location --retry 2 "$url" --output "$archive.part"
    mv "$archive.part" "$archive"
  fi
  local actual
  if command -v sha256sum >/dev/null; then
    actual="$(sha256sum "$archive")"
  else
    actual="$(shasum -a 256 "$archive")"
  fi
  [[ "${actual%% *}" == "$checksum" ]] || {
    echo "Checksum mismatch: $archive" >&2
    return 1
  }
  if [[ ! -d "$matrix_root/source/$name-$version" ]]; then
    tar -xzf "$archive" -C "$matrix_root/source"
  fi
}

fetch_source openssl 4.0.0 https://github.com/openssl/openssl/releases/download/openssl-4.0.0/openssl-4.0.0.tar.gz c32cf49a959c4f345f9606982dd36e7d28f7c58b19c2e25d75624d2b3d2f79ac
fetch_source nghttp3 1.15.0 https://github.com/ngtcp2/nghttp3/releases/download/v1.15.0/nghttp3-1.15.0.tar.gz 0e431c81eb2d3df5ced048d6e942925ff922ad053e76a0274eea7b164c9b776e
fetch_source ngtcp2 1.22.1 https://github.com/ngtcp2/ngtcp2/releases/download/v1.22.1/ngtcp2-1.22.1.tar.gz 063d80531acac0ddbbc1b9d12829a824edc2abe8dba2e632fd1ce15cfd5632f9
fetch_source curl 8.23.0 https://curl.se/download/curl-8.23.0.tar.gz e3de77cfa6367083c776a26647fc9f633b538c06c3baa73d931a252ac8f72b49

(
  cd "$matrix_root/source/openssl-4.0.0"
  ./Configure --prefix="$matrix_prefix" --libdir=lib no-tests no-shared
  make -j"$matrix_jobs"
  make install_sw
)
cmake -S "$matrix_root/source/nghttp3-1.15.0" -B "$matrix_root/nghttp3-build" \
  -DCMAKE_INSTALL_PREFIX="$matrix_prefix" -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=OFF
cmake --build "$matrix_root/nghttp3-build" -j"$matrix_jobs"
cmake --install "$matrix_root/nghttp3-build"
cmake -S "$matrix_root/source/ngtcp2-1.22.1" -B "$matrix_root/ngtcp2-build" \
  -DCMAKE_INSTALL_PREFIX="$matrix_prefix" -DCMAKE_PREFIX_PATH="$matrix_prefix" \
  -DOPENSSL_ROOT_DIR="$matrix_prefix" -DENABLE_LIB_ONLY=ON \
  -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF
cmake --build "$matrix_root/ngtcp2-build" -j"$matrix_jobs"
cmake --install "$matrix_root/ngtcp2-build"

matrix_ca_args=()
for matrix_ca in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
  if [[ -f "$matrix_ca" ]]; then
    matrix_ca_args+=("-DCURL_CA_BUNDLE=$matrix_ca")
    break
  fi
done
cmake -S "$matrix_root/source/curl-8.23.0" -B "$matrix_root/curl-build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$matrix_prefix" \
  -DCMAKE_PREFIX_PATH="$matrix_prefix" -DOPENSSL_ROOT_DIR="$matrix_prefix" \
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DCURL_USE_OPENSSL=ON \
  -DUSE_NGTCP2=ON -DUSE_PROXY_HTTP3=ON -DUSE_NGHTTP2=OFF \
  -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF "${matrix_ca_args[@]}"
cmake --build "$matrix_root/curl-build" -j"$matrix_jobs"
cmake --install "$matrix_root/curl-build"
"$matrix_prefix/bin/curl" --version
"$matrix_prefix/bin/curl" --help proxy
