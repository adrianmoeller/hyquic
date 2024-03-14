#!/bin/bash

if [ "$1" = "clean" ]; then
	rm -rf *.pem *.ext
	exit 0
fi

# create CA and install it
openssl req -newkey rsa:2048 -nodes -keyout ca-key-u.pem -x509 -days 365 -out ca-cert-u.pem -subj "/C=DE/ST=Hesse/L=DA/O=TUD/CN=Adrian Moeller/emailAddress=adrian.moeller@stud.tu-darmstadt.de"
if [ -d /etc/pki/ca-trust/source/anchors/ ]; then
	cp ca-cert-u.pem /etc/pki/ca-trust/source/anchors/ca-cert-u.pem
	update-ca-trust
elif [ -d /usr/local/share/ca-certificates/ ]; then
	cp ca-cert-u.pem /usr/local/share/ca-certificates/ca-cert-u.crt
	update-ca-certificates
fi

cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = server.test
EOF

# create server cert and sign it
openssl req -newkey rsa:2048 -nodes -keyout server-key-u.pem -out server-req-u.pem -subj "/C=DE/ST=Hesse/L=DA/O=TUD/CN=Adrian Moeller/emailAddress=adrian.moeller@stud.tu-darmstadt.de"
openssl x509 -req -days 186 -set_serial 01 -in server-req-u.pem -out server-cert-u.pem -CA ca-cert-u.pem -CAkey ca-key-u.pem -extfile server.ext

# create client cert and sign it
openssl req -newkey rsa:2048 -nodes -keyout client-key-u.pem -out client-req-u.pem -subj "/C=DE/ST=Hesse/L=DA/O=TUD/CN=Adrian Moeller/emailAddress=adrian.moeller@stud.tu-darmstadt.de"
openssl x509 -req -days 186 -set_serial 01 -in client-req-u.pem -out client-cert-u.pem -CA ca-cert-u.pem -CAkey ca-key-u.pem
