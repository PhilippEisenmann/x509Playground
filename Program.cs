namespace certificate_tool;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

class Program
{
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
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
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

    /// <summary>
    /// Print all certificate extensions
    /// </summary>
    /// <param name="SubjectDistinguishedName">The subject distinguished name i.e. 'CN=email@domain.TLD'</param>  
    /// <param name="X509StoreLocation">The store location to search the DN for.</param>
    public static void Main(string[] args )
    {
        string SubjectDistinguishedName = "";
        StoreLocation X509StoreLocation = StoreLocation.CurrentUser;

       if(args.Count() < 2)
       {
        Console.WriteLine("need 2 arguments, SubjectDistinguishedName and X509StoreLocation");
       }
       else{
            SubjectDistinguishedName = args[0];
            switch (args[1])
            {
                case "LocalMachine" : X509StoreLocation = StoreLocation.LocalMachine; break;
            }
       }        

       X509Certificate2 cert = GetCertificateFromStore(SubjectDistinguishedName, X509StoreLocation);
        if (cert == null)
        {
            Console.WriteLine("Certificate {0} not found.", SubjectDistinguishedName);
            return;
        }
        
        foreach (X509Extension extension in cert.Extensions)
        {
        // Create an AsnEncodedData object using the extensions information.
        AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
        Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
        Console.WriteLine("Oid value: {0}",asndata.Oid.Value);
        Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
        Console.WriteLine(asndata.Format(true));
        }
    }
}
