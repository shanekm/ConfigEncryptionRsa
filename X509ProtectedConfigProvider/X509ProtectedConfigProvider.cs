namespace X509ProtectedConfig
{
    using System.Collections.Specialized;
    using System.Configuration;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Security.Cryptography.Xml;
    using System.Xml;

    public class X509ProtectedConfigProvider : ProtectedConfigurationProvider
    {
        private X509Certificate2 cert;

        private string keyName = "rsaKey";

        private RSACryptoServiceProvider rsaKey;

        public override XmlNode Decrypt(XmlNode encryptedNode)
        {
            // Load config section to encrypt into xmlDocument instance
            XmlDocument doc = encryptedNode.OwnerDocument;
            EncryptedXml eXml = new EncryptedXml(doc);

            // Add a key-name mapping. This method can only decrypt documents that present the specified key name.
            eXml.AddKeyNameMapping(this.keyName, this.rsaKey);

            eXml.DecryptDocument();
            return doc.DocumentElement;
        }

        public override XmlNode Encrypt(XmlNode node)
        {
            // Load config section to encrypt into xmlDocument instance
            XmlDocument doc = new XmlDocument { PreserveWhitespace = true };
            doc.LoadXml(node.OuterXml);

            // Create Rijndael key.
            RijndaelManaged sessionKey = new RijndaelManaged();
            sessionKey.KeySize = 256;

            EncryptedXml eXml = new EncryptedXml();
            XmlElement elementToEncrypt = (XmlElement)node;

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);
            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;

            edElement.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Encrypt the session key and add it to an EncryptedKey element.
            EncryptedKey ek = new EncryptedKey();
            byte[] encryptedKey = EncryptedXml.EncryptKey(sessionKey.Key, this.rsaKey, false);
            ek.CipherData = new CipherData(encryptedKey);
            ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);

            // Set the KeyInfo element to specify the name of the RSA key.
            edElement.KeyInfo = new KeyInfo();
            KeyInfoName kin = new KeyInfoName();
            kin.Value = this.keyName;

            // Add the KeyInfoName element to the  
            // EncryptedKey object.
            ek.KeyInfo.AddClause(kin);
            edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

            // Add the encrypted element data to the  
            // EncryptedData object.
            edElement.CipherData.CipherValue = encryptedElement;

            // EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
            return edElement.GetXml();
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            base.Initialize(name, config);

            string certSubjectDistName = config["CertSubjectDistinguishedName"];
            string certStoreName = config["CertStoreName"];

            X509Store certStore = !string.IsNullOrEmpty(certStoreName)
                                      ? new X509Store(certStoreName, StoreLocation.LocalMachine)
                                      : new X509Store(StoreLocation.LocalMachine);

            try
            {
                certStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = certStore.Certificates.Find(
                    X509FindType.FindBySubjectName, 
                    certSubjectDistName, 
                    true);

                this.cert = certs.Count > 0 ? certs[0] : null;
                this.rsaKey = this.cert.PrivateKey as RSACryptoServiceProvider;
            }
            finally
            {
                certStore.Close();
            }
        }
    }
}