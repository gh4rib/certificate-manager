#!/bin/bash

# --- CONFIGURATION ---
DIR_ROOT="./pki"
DIR_CA="$DIR_ROOT/ca"
DIR_SERVERS="$DIR_ROOT/servers"
DIR_USERS="$DIR_ROOT/users"
DIR_CRL="$DIR_ROOT/crl"

CA_KEY="$DIR_CA/ca.key"
CA_CERT="$DIR_CA/ca.crt"
CONF="$DIR_CA/openssl.cnf"
DB_INDEX="$DIR_CA/index.txt"
DB_SERIAL="$DIR_CA/serial"
CRL_FILE="$DIR_CRL/crl.pem"

# ALGORITHM SETTINGS (ecc or rsa)
ALGO="ecc"
ECC_CURVE="prime256v1"
RSA_BITS="2048"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

mkdir -p "$DIR_CA" "$DIR_SERVERS" "$DIR_USERS" "$DIR_CRL"

# --- INTERNAL HELPERS ---

get_key_args() {
    if [ "$ALGO" == "ecc" ]; then
        echo "-newkey ec -pkeyopt ec_paramgen_curve:$ECC_CURVE"
    else
        echo "-newkey rsa:$RSA_BITS"
    fi
}

# Generates a local OpenSSL config file to manage the database
create_config() {
    cat > "$CONF" <<EOF
[ ca ]
default_ca = my_ca

[ my_ca ]
dir = $DIR_CA
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/ca.crt
serial = \$dir/serial
private_key = \$dir/ca.key
default_days = 825
default_crl_days = 30
default_md = sha256
policy = policy_loose
copy_extensions = copy

[ policy_loose ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
distinguished_name = req_distinguished_name
string_mask = utf8only
x509_extensions = v3_ca

[ req_distinguished_name ]
commonName = Common Name

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ server_ext ]
basicConstraints = CA:FALSE
nsCertType = server
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
authorityKeyIdentifier = keyid,issuer

[ client_ext ]
basicConstraints = CA:FALSE
nsCertType = client, email
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
authorityKeyIdentifier = keyid,issuer
EOF
}

check_ca() {
    if [[ ! -f "$CA_KEY" || ! -f "$DB_INDEX" ]]; then
        echo -e "${BLUE}PKI not initialized. Please Run Option 1 first.${NC}"
        return 1
    fi
    return 0
}

# --- MAIN MENU FUNCTIONS ---

# 1. Initialize CA and Database
init_ca() {
    if [[ -f "$CA_KEY" ]]; then
        echo "CA already exists."
    else
        echo -e "${GREEN}Initializing PKI Database & CA...${NC}"
        create_config
        mkdir -p "$DIR_CA/newcerts"
        touch "$DB_INDEX"
        echo "1000" > "$DB_SERIAL"

        read -p "Enter CA Name (e.g., HomeLab Root): " CN_NAME

        # Generate CA Key and Self-Signed Cert
        openssl req -x509 -new -nodes $(get_key_args) -keyout "$CA_KEY" \
            -sha256 -days 3650 -out "$CA_CERT" \
            -config "$CONF" -extensions v3_ca \
            -subj "/O=HomeLab/CN=$CN_NAME"

        echo -e "${GREEN}CA Ready at $DIR_CA${NC}"
    fi
}

# 2. Generate Server Certificate (Smart IP/DNS Detection)
gen_server() {
    check_ca || return
    read -p "Enter Server Domain or IP (e.g., 192.168.1.50): " DOMAIN
    
    mkdir -p "$DIR_SERVERS/$DOMAIN"
    KEY="$DIR_SERVERS/$DOMAIN/server.key"
    CSR="$DIR_SERVERS/$DOMAIN/server.csr"
    CRT="$DIR_SERVERS/$DOMAIN/server.crt"

    echo -e "${GREEN}Creating Server Cert for $DOMAIN...${NC}"

    # DETECT IF INPUT IS IP OR DNS
    if [[ "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        SAN="IP:$DOMAIN"    # Use IP tag
    else
        SAN="DNS:$DOMAIN"   # Use DNS tag
    fi

    # 1. Gen Key & CSR
    openssl req -new -nodes $(get_key_args) -keyout "$KEY" -out "$CSR" \
        -subj "/O=HomeLab/CN=$DOMAIN" \
        -addext "subjectAltName = $SAN"

    # 2. Sign with CA
    openssl ca -config "$CONF" -batch -notext -in "$CSR" -out "$CRT" \
        -extensions server_ext

    rm "$CSR"
    echo -e "${GREEN}Server Cert Created ($SAN): $CRT${NC}"
}

# 3. Generate User Certificate
gen_user() {
    check_ca || return
    read -p "Enter Username (e.g., alice): " USERNAME
    read -s -p "Enter Export Password: " P12_PASS
    echo ""

    mkdir -p "$DIR_USERS/$USERNAME"
    KEY="$DIR_USERS/$USERNAME/$USERNAME.key"
    CSR="$DIR_USERS/$USERNAME/$USERNAME.csr"
    CRT="$DIR_USERS/$USERNAME/$USERNAME.crt"
    P12="$DIR_USERS/$USERNAME/$USERNAME.p12"

    echo -e "${GREEN}Creating mTLS Cert for $USERNAME...${NC}"

    # 1. Gen Key & CSR
    openssl req -new -nodes $(get_key_args) -keyout "$KEY" -out "$CSR" \
        -subj "/O=HomeLab/OU=Users/CN=$USERNAME"

    # 2. Sign with CA (Database Update)
    openssl ca -config "$CONF" -batch -notext -in "$CSR" -out "$CRT" \
        -extensions client_ext

    # 3. Export P12
    openssl pkcs12 -export -out "$P12" -inkey "$KEY" -in "$CRT" \
        -certfile "$CA_CERT" -passout pass:"$P12_PASS"

    rm "$CSR"
    echo -e "${GREEN}User P12 Ready: $P12${NC}"
}

# 4. Revoke a User
revoke_user() {
    check_ca || return
    read -p "Enter Username to Revoke: " USERNAME
    CRT="$DIR_USERS/$USERNAME/$USERNAME.crt"

    if [[ ! -f "$CRT" ]]; then
        echo -e "${RED}Certificate not found: $CRT${NC}"
        return
    fi

    echo -e "${RED}Revoking certificate for $USERNAME...${NC}"

    # Revoke in Database
    openssl ca -config "$CONF" -revoke "$CRT"

    # Regenerate CRL
    gen_crl
}

# 5. Generate/Update CRL
gen_crl() {
    check_ca || return
    echo -e "${BLUE}Generating updated CRL...${NC}"

    openssl ca -config "$CONF" -gencrl -out "$CRL_FILE"

    echo -e "${GREEN}CRL Created: $CRL_FILE${NC}"
    echo "Upload this file to your Nginx/Server."
}

# --- MENU ---
while true; do
    echo -e "\n${BLUE}--- PKI Manager (Revocation Enabled) ---${NC}"
    echo "1. Init CA & Database"
    echo "2. Create Server Cert"
    echo "3. Create User Cert"
    echo "4. Revoke User Cert"
    echo "5. Update CRL (Generate crl.pem)"
    echo "6. Exit"
    read -p "Select: " OPT
    case $OPT in
        1) init_ca ;;
        2) gen_server ;;
        3) gen_user ;;
        4) revoke_user ;;
        5) gen_crl ;;
        6) exit 0 ;;
        *) echo "Invalid" ;;
    esac
done
