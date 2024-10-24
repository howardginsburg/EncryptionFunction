# Encryption Function

This Azure Function project serves as a sample that takes a request body, encrypt and signs it using a keys in key vault key, and returns the encrypted data.

## Getting Started

This project contains a DevContainer configuration.  You can open it in GitHub Codespaces or install Docker and Visual Studio Code.

1. Deploy an instance of Azure Key Vault that uses the RBAC permission model.
1. Grant your Entra ID `Key Vault Administrator` permissions to the Key Vault.
1. Create the keys needed for encryption, decryption, and signing.
1. Clone or Fork the repository.
1. Rename the `local.settings.json.example` file to `local.settings.json` and update the values with your Azure Key Vault and key names.
1. Open a terminal and run `az login` to authenticate with Azure.  This will enable the DefaultCredential to authenticate as you with Azure Key Vault.

## Deployment

1. Create an Azure Function resource.
1. Enable the Managed Identity for the Azure Function.
1. Grant the Managed Identity `Key Vault Crypto User` permissions to the Key Vault.
1. Deploy the Azure Function code to the Azure Function resource.
1. Test the Azure Function by sending a POST request with a JSON body to the Azure Function URL.