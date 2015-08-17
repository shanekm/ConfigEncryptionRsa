namespace ConfigEncryptionRsa
{
    using System;
    using System.Data;
    using System.Security.Cryptography.X509Certificates;
    using System.Xml;
    using Microsoft.Practices.EnterpriseLibrary.Data;

    public class Program
    {
        private static readonly string appName = "ConfigEncryptionRsa.exe";

        private static void Main(string[] args)
        {
            // TestCertificates();
            do
            {
                while (!Console.KeyAvailable)
                {
                    Console.Write("(V)iewConfig | (P)rotect | (U)nprotect | (D)ataBase: ");
                    ConsoleKeyInfo cki = Console.ReadKey();
                    Console.WriteLine();

                    switch (cki.Key.ToString())
                    {
                        case "P":
                            ConfigSecurity.ProtectConfiguration("connectionStrings");
                            break;

                        case "U":
                            ConfigSecurity.UnProtectConfiguration("connectionStrings");
                            break;

                        case "D":
                            ReadDb();
                            break;

                        default:
                            ViewConfig();
                            break;
                    }
                }
            }
            while (Console.ReadKey(true).Key != ConsoleKey.Escape);
        }

        private static void ViewConfig()
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(AppDomain.CurrentDomain.SetupInformation.ConfigurationFile);
            Console.WriteLine(xmlDoc.InnerXml);
        }

        private static void ReadDb()
        {
            // Test DB access
            DatabaseFactory.SetDatabaseProviderFactory(new DatabaseProviderFactory());
            Database db = DatabaseFactory.CreateDatabase("MyDbConnStr");

            //string connStr = ConfigSecurity.DecryptConnectionString("MyDbConnStr");
            Console.WriteLine("DbConnString: " + db.ConnectionString);

            IDataReader reader = db.ExecuteReader(CommandType.Text, "SELECT TOP 5 * FROM TransactionActivity");
            while (reader.Read())
            {
                Console.WriteLine("Result: {0} {1} {2}", reader[0], reader[3], reader[4], reader[5]);
            }
        }

        private static void TestCertificates()
        {
            // Load certificate from cert store (user/computer store = MY = Personal)
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            // ... do work
            foreach (var cert in store.Certificates)
            {
                // validate certificates
                var chain = new X509Chain();
                var policy = new X509ChainPolicy
                                 {
                                     RevocationFlag = X509RevocationFlag.EntireChain, 
                                     RevocationMode = X509RevocationMode.Online, 
                                     UrlRetrievalTimeout = TimeSpan.FromMilliseconds(10000)
                                 };

                chain.ChainPolicy = policy;
                if (!chain.Build(cert))
                {
                    // do some work
                }

                Console.WriteLine(cert.FriendlyName);
            }

            store.Close();
        }
    }
}