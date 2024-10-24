import os
import json
import logging
import base64
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm, EncryptionAlgorithm
import hashlib
import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="encrypt")
def encrypt(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Encrypt function triggered.')

    try:
        # Parse JSON payload
        req_body = req.get_json()
        payload = json.dumps(req_body).encode('utf-8')

        # Access Key Vault
        credential = DefaultAzureCredential()
        vault_url = os.getenv('AZURE_KEY_VAULT_ENDPOINT')
        key_vault_client = KeyClient(vault_url=vault_url, credential=credential)

        # Get the encryption key and encrypt the payload
        encryp_key_name = os.getenv('ENCRYPT_KEY_NAME')
        encrypt_key = key_vault_client.get_key(encryp_key_name)
        encrypt_client = CryptographyClient(encrypt_key, credential)
        encrypted_payload = encrypt_client.encrypt(EncryptionAlgorithm.rsa_oaep, payload).ciphertext

        # Retrieve the signing key
        signing_key_name = os.getenv('SIGNING_KEY_NAME')
        signing_key = key_vault_client.get_key(signing_key_name)

        # Create a CryptographyClient for signing
        signing_client = CryptographyClient(signing_key, credential)

        # Sign the encrypted payload
        hashed_encrypted_payload = hashlib.sha256(encrypted_payload).digest()
        sign_result = signing_client.sign(SignatureAlgorithm.rs256, hashed_encrypted_payload)

        # Encode the signature in base64
        encoded_signature = base64.b64encode(sign_result.signature).decode('utf-8')

        # Return the encrypted payload and the signature
        return func.HttpResponse(
            json.dumps({"encrypted_payload": base64.b64encode(encrypted_payload).decode('utf-8'), "signature": encoded_signature}),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(
            "An error occurred while processing the request.",
            status_code=500
        )

@app.route(route="decrypt")
def decrypt(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Decrypt function triggered.')

    try:
        # Parse JSON payload
        req_body = req.get_json()
        encrypted_payload = base64.b64decode(req_body["encrypted_payload"])
        signature = base64.b64decode(req_body["signature"])

        # Hash the encrypted payload using SHA-256
        hashed_encrypted_payload = hashlib.sha256(encrypted_payload).digest()

        # Access Key Vault
        credential = DefaultAzureCredential()
        vault_url = os.getenv('AZURE_KEY_VAULT_ENDPOINT')
        key_vault_client = KeyClient(vault_url=vault_url, credential=credential)

        # Retrieve the signing key
        signing_validation_key_name = os.getenv('SIGNING_VALIDATION_KEY_NAME')
        signing_validation_key = key_vault_client.get_key(signing_validation_key_name)

        # Create a CryptographyClient for verifying
        verifying_client = CryptographyClient(signing_validation_key, credential)

        # Verify the signature
        verify_result = verifying_client.verify(SignatureAlgorithm.rs256, hashed_encrypted_payload, signature)
        if not verify_result.is_valid:
            return func.HttpResponse(
                "Invalid signature.",
                status_code=400
            )

        # Retrieve the encryption key
        decrypt_key_name = os.getenv('DECRYPT_KEY_NAME')
        decrypt_key = key_vault_client.get_key(decrypt_key_name)

        # Create a CryptographyClient for decrypting
        decryption_client = CryptographyClient(decrypt_key, credential)

        # Decrypt the payload
        decrypt_result = decryption_client.decrypt(EncryptionAlgorithm.rsa_oaep, encrypted_payload)
        decrypted_payload = decrypt_result.plaintext.decode('utf-8')

        # Return the decrypted JSON payload
        return func.HttpResponse(
            decrypted_payload,
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(
            "An error occurred while processing the request.",
            status_code=500
        )