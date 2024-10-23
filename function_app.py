import os
import logging
import json
import base64
import hashlib
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import padding
#from cryptography.hazmat.primitives.serialization import load_pem_private_key
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, SignatureAlgorithm
import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="encrypt")
def encrypt(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Parse JSON payload
        req_body = req.get_json()
        payload = json.dumps(req_body).encode('utf-8')

         # Hash the payload using SHA-256
        hashed_payload = hashlib.sha256(payload).digest()

        # Access Key Vault
        credential = DefaultAzureCredential()
        vault_url = os.getenv('AZURE_KEY_VAULT_ENDPOINT')
        

        # Retrieve the certificate
        #certificate_client = CertificateClient(vault_url=vault_url, credential=credential)
        #certificate_name = os.getenv('CERTIFICATE_NAME')
        #certificate = certificate_client.get_certificate(certificate_name)

         # Retrieve the private key
        key_client = KeyClient(vault_url=vault_url, credential=credential)
        key_name = os.getenv('KEY_NAME')
        key = key_client.get_key(key_name)
       
       
        # Create a CryptographyClient
        crypto_client = CryptographyClient(key, credential)

        # Sign the payload
        sign_result = crypto_client.sign(SignatureAlgorithm.rs256, hashed_payload)

        # Encode the signature in base64
        encoded_signature = base64.b64encode(sign_result.signature).decode('utf-8')

        # Return the signed payload
        return func.HttpResponse(
            json.dumps({"payload": req_body, "signature": encoded_signature}),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(
            "An error occurred while processing the request.",
            status_code=500
        )