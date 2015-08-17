namespace ConfigEncryptionRsa
{
    using System.Configuration;

    public static class ConfigSecurity
    {
        public static void ProtectConfiguration(string sectionName)
        {
            Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            ConfigurationSection configurationSection = config.GetSection(sectionName);

            if (configurationSection != null)
            {
                if (!configurationSection.SectionInformation.IsProtected)
                {
                    if (!configurationSection.SectionInformation.IsLocked)
                    {
                        configurationSection.SectionInformation.ProtectSection("X509ProtectedConfigProvider");
                        configurationSection.SectionInformation.ForceSave = true;
                        config.Save(ConfigurationSaveMode.Full);
                    }
                }
            }
        }

        public static void UnProtectConfiguration(string sectionName)
        {
            Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            ConfigurationSection configurationSection = config.GetSection(sectionName);

            // Get the section to unprotect.
            ConfigurationSection connStrings = config.ConnectionStrings;

            if (connStrings != null)
            {
                if (connStrings.SectionInformation.IsProtected)
                {
                    if (!connStrings.ElementInformation.IsLocked)
                    {
                        // Unprotect the section.
                        connStrings.SectionInformation.UnprotectSection();

                        connStrings.SectionInformation.ForceSave = true;
                        config.Save(ConfigurationSaveMode.Full);
                    }
                }
            }
        }

        public static string DecryptConnectionString(string connStringName)
        {
            Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            ConnectionStringsSection conStrSection = config.ConnectionStrings as ConnectionStringsSection;

            return conStrSection.ConnectionStrings[connStringName].ConnectionString;
        }
    }
}