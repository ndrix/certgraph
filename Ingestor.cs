using System;
using System.Collections.Generic;
using System.Text;
using CertGraph.CLI.Models;
using System.Runtime.Caching;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace CertGraph.CLI
{
    class Ingestor
    {
        const string HttpsPrefix = "https://";

        protected List<Cert> _chain;

        /// <summary>
        /// Makes a TLS connection, creates the chain and returns all the certificates in 
        /// the chain
        /// </summary>
        /// <param name="hostname"></param>
        /// <param name="chain"></param>
        /// <param name="timeout"></param>
        /// <returns></returns>
        public bool GetCert(string hostname, out List<Cert> chain, int timeout = 3000)
        {
            #region parse hostname, normalize it for cache lookup
            if (!hostname.StartsWith(HttpsPrefix))
            {
                if (hostname.StartsWith("//"))
                    hostname = hostname.Substring(2);

                hostname = HttpsPrefix + hostname;
            }
            #endregion

            /// all ok, we can connect now and get the chainz, yo
            try
            {
                if (Uri.TryCreate(hostname, UriKind.Absolute, out Uri tmp))
                {
                    TcpClient client = new TcpClient();
                    if (client.ConnectAsync(tmp.Host, tmp.Port).Wait(timeout))
                    {
                        SslStream s = new SslStream(client.GetStream(), 
                                                    false, // leave conn open
                                                    new RemoteCertificateValidationCallback(IngestCertChain), 
                                                    null); // local cert callback
                        s.ReadTimeout = timeout;
                        s.WriteTimeout = timeout;
                        s.AuthenticateAsClient(tmp.Host);
                        client.Close();
                        chain = _chain;
                        return true;
                    }
                    else
                    {
                        System.Diagnostics.Trace.TraceError($"Could not connect to {hostname}, {tmp.Host} pot {tmp.Port}");
                        chain = null;
                        return false;
                    }
                }
                else
                {
                    System.Diagnostics.Trace.TraceError($"Could not resolve url: {hostname}");
                    chain = null;
                    return false;
                }
            }
            catch (Exception ex)
            {
                // Probably a wrong hostname or host is down
                System.Diagnostics.Trace.TraceWarning($"Exception connecting to url: {hostname} + {ex.Message}");
                chain = null;
                return false;
            }

        }

        /// <summary>
        /// Take each cert from the chain, return them as a List of <Cert>'s
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="origcert"></param>
        /// <param name="chain"></param>
        /// <param name="sslPolicyErrors"></param>
        /// <returns>true</returns>
        private bool IngestCertChain(object sender, X509Certificate origcert, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            _chain = new List<Cert> { };
            
            foreach (X509ChainElement ce in chain.ChainElements)
            {
                X509Certificate2 c = ce.Certificate;
                _chain.Add(new Cert()
                {
                    name = c.FriendlyName, // needed?
                    serial = c.SerialNumber,
                    subject = c.Subject,
                    expiry = c.GetExpirationDateString(),
                    thumbprint = c.Thumbprint,
                    issuer = c.Issuer
                });
            }
            _chain.Reverse(); /// We want root -> int -> [int*N] -> leaf

            /// always return true, we never fail.  We just wanted the chain
            return true;
        }
    }
}
