namespace certificate_tool;
using System;
using System.Net.Security;
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.CompilerServices;

class Program
{

    static void ReadAllSettings()
    {
        try
        {
            var appSettings = ConfigurationManager.AppSettings;

            if (appSettings.Count == 0)
            {
                Console.WriteLine("AppSettings is empty.");
            }
            else
            {
                foreach (var key in appSettings.AllKeys)
                {
                    Console.WriteLine("Key: {0} Value: {1}", key, appSettings[key]);
                }
            }
        }
        catch (ConfigurationErrorsException)
        {
            Console.WriteLine("Error reading app settings");
        }
    }

    private static X509Certificate2 GetCertificateFromStore(string certName, StoreLocation location)
    {
        // Get the certificate store for the current user.
        X509Store store = new X509Store(location);
        try
        {
            store.Open(OpenFlags.ReadOnly);

            // Place all certificates in an X509Certificate2Collection object.
            X509Certificate2Collection certCollection = store.Certificates;
            // If using a certificate with a trusted root you do not need to FindByTimeValid, instead:
            // currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
            //X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, true);
            X509Certificate2Collection signingCert = certCollection.Find(X509FindType.FindBySubjectDistinguishedName, certName, true);
            if (signingCert.Count == 0)
                return null;
            // Return the first certificate in the collection, has the right name and is current.
            return signingCert[0];
        }
        finally
        {
            store.Close();
        }
    }

    private static void printCertificateExtensions(X509ExtensionCollection col)
    {
        foreach (X509Extension ext in col)
        {
            // Create an AsnEncodedData object using the extensions information.
            // SAN: 2.5.29.17
            AsnEncodedData asndata = new AsnEncodedData(ext.Oid, ext.RawData);
            Console.WriteLine("Extension type: {0}", ext.Oid.FriendlyName);
            Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
            Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
            Console.WriteLine(asndata.Format(true));
        }
    }

    private static bool ValidateServerCertificate(HttpRequestMessage request, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors)
    {
        // Perform custom server certificate validation if required
        // Return true if the certificate is trusted, false otherwise

        Console.WriteLine("Subject: {0}", certificate.Subject);
        Console.WriteLine("---------------------------------------");
        printCertificateExtensions(certificate.Extensions);

        foreach (var chainElements in chain.ChainElements)
        {
            Console.WriteLine("Subject: {0}", chainElements.Certificate.Subject);
            Console.WriteLine("---------------------------------------");
            printCertificateExtensions(chainElements.Certificate.Extensions);
        }

        //ToDo
        return true;
    }


    private static async void webcall(X509Certificate2 clientCertificate)
    {
        //enable certficate chechking
        //https://learn.microsoft.com/en-us/dotnet/api/system.net.http.httpclienthandler.checkcertificaterevocationlist?view=net-8.0
        System.Net.ServicePointManager.CheckCertificateRevocationList = true;

        // Create an HttpClient with MTLS authentication
        HttpClient httpClient = new HttpClient(new HttpClientHandler
        {
            ClientCertificateOptions = ClientCertificateOption.Manual,
            ServerCertificateCustomValidationCallback = ValidateServerCertificate,
            ClientCertificates = { clientCertificate }
        });

        try
        {


            // Send the webhook request
            HttpResponseMessage response = httpClient.GetAsync(ConfigurationManager.AppSettings["url"]).Result;
            string responseBody = await response.Content.ReadAsStringAsync();

            Console.Write("HTTP Status: {0}", response.StatusCode);
            foreach (var kp in response.Content.Headers)
            {
                Console.Write("HTTP ResponseHeader: KEY:{0} Value:{1}", kp.Key, kp.Value);
            }
            Console.Write("HTTP Content: {0}", responseBody);
        }
        catch (Exception exp)
        {
            Console.Write("Exeption: {0}", exp.ToString());
        }
    }

    /// <summary>
    /// Print all certificate extensions
    /// </summary>
    /// <param name="SubjectDistinguishedName">The subject distinguished name i.e. 'CN=email@domain.TLD'</param>  
    /// <param name="X509StoreLocation">The store location to search the DN for.</param>
    public static void Main(string[] args)
    {
        ReadAllSettings();

        string SubjectDistinguishedName = ConfigurationManager.AppSettings["SubjectDistinguishedName"] ?? string.Empty;
        if (string.Empty == SubjectDistinguishedName)
        {
            Console.WriteLine("Error Reading AppSetting: SubjectDistinguishedName");
            return;
        }

        StoreLocation X509StoreLocation = StoreLocation.CurrentUser;
        string X509StoreLocationStr = ConfigurationManager.AppSettings["X509StoreLocation"] ?? string.Empty;
        if (string.Empty == X509StoreLocationStr && !Enum.TryParse(X509StoreLocationStr, true, out X509StoreLocation))
        {
            Console.WriteLine("Error Reading AppSetting: X509StoreLocationStr");
            return;
        }

        X509Certificate2 cert = GetCertificateFromStore(SubjectDistinguishedName, X509StoreLocation);
        if (cert == null)
        {
            Console.WriteLine("Certificate {0} not found.", SubjectDistinguishedName);
            return;
        }

        printCertificateExtensions(cert.Extensions);
        webcall(cert);
    }
}
