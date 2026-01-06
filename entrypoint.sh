#!/bin/bash
set -e

if [ ! -f "$APP_KS_PATH" ]; then
    echo "keystore not found"
    keytool -genkeypair \
        -alias "$APP_KS_ALIAS" \
        -keyalg RSA \
        -keysize 2048 \
        -storetype PKCS12 \
        -keystore "$APP_KS_PATH" \
        -validity 3650 \
        -storepass "$APP_KS_PSWD" \
        -keypass "$APP_KS_PSWD" \
        -dname "CN=babaika, OU=IT, O=Alfa, L=Moscow, S=MSK, C=RU"
    echo "keystore generated"
fi

exec java -jar app.jar