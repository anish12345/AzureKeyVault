using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using System.Net;
using System.Text;

string tenantId = "dd393912-1b31-48f1-b206-c7273175d5b8";
string clientId = "5350486d-d5fa-4e9d-86b3-54d1a0ce9ce2";
string clientSecret = "MhU8Q~Yt6bm8~IrhUYCUgXuhM7zXe-_b7hkrhaVa";

string keyvaultUrl = "https://anishkeyvault786.vault.azure.net/";
string keyName = "anishappkey";
string textToEncrypt = "This a secret text";

ClientSecretCredential clientSecretCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);
KeyClient keyClient = new KeyClient(new Uri(keyvaultUrl), clientSecretCredential);

var key = keyClient.GetKey(keyName);

// The CryptographyClient class is part of the Azure Key vault package
// This is used to perform cryptographic operations with Azure Key Vault keys
var cryptoClient = new CryptographyClient(key.Value.Id, clientSecretCredential);

// We first need to take the bytes of the string that needs to be converted

byte[] textToBytes = Encoding.UTF8.GetBytes(textToEncrypt);

EncryptResult result = cryptoClient.Encrypt(EncryptionAlgorithm.RsaOaep, textToBytes);

Console.WriteLine("The encrypted text");
Console.WriteLine(Convert.ToBase64String(result.Ciphertext));

// Now lets decrypt the text
// We first need to convert our Base 64 string of the Cipertext to bytes

byte[] ciperToBytes = result.Ciphertext;

DecryptResult textDecrypted = cryptoClient.Decrypt(EncryptionAlgorithm.RsaOaep, ciperToBytes);

Console.WriteLine(Encoding.UTF8.GetString(textDecrypted.Plaintext));

Console.ReadKey();







