import os
import logging
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from azure.identity import DefaultAzureCredential
from azure.keyvault.certificates import CertificateClient
import azure.functions as func

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="encrypt")
def encrypt(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    try:
        # Parse JSON payload
        req_body = req.get_json()
        payload = json.dumps(req_body).encode('utf-8')

        # Access Key Vault
        credential = DefaultAzureCredential()
        vault_url = os.getenv('AZURE_KEY_VAULT_ENDPOINT')
        certificate_client = CertificateClient(vault_url=vault_url, credential=credential)

        # Retrieve the certificate
        certificate_name = os.getenv('CERTIFICATE_NAME')
        certificate = certificate_client.get_certificate(certificate_name)
        private_key = load_pem_private_key(certificate.key_id, password=None)

        # Sign the payload
        signature = private_key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Encode the signature in base64
        encoded_signature = base64.b64encode(signature).decode('utf-8')

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