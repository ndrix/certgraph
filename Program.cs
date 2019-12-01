/*
 * Gets certs and makes JSON objects out of it
 * Author: Michael Hendrickx
 * Code: https://github.com/ndrix
 * 
 */

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using CertGraph.CLI.Models;
using Newtonsoft.Json;

namespace CertGraph.CLI
{
    class Program
    {


        static void PrintUsage()
        {
            Console.WriteLine("./certgraph.exe [OPTIONS]\n");
            Console.WriteLine("Where OPTIONS are:");
            Console.WriteLine("   --timeout <n>: wait n ms between GET's (default 3000)");
            Console.WriteLine("   --input   <f>: read hostnames from <f>");
            Console.WriteLine("   --output  <d>: store our JSON files in <d>");
            Console.WriteLine("   --help       : this screen");
            Environment.Exit(1);
        }

        /// <summary>
        ///  A generic emergency break function
        /// </summary>
        /// <param name="s"></param>
        static void Die(string s, object arg = null)
        {
            Console.WriteLine(" [e] Error: " + s, arg);
            Environment.Exit(-1);
        }


        static void Main(string[] args)
        {
            Console.WriteLine(" CertGraph v1.0");
            Console.WriteLine("----------------------");


            string inputFile = string.Empty;
            string inputHostName = string.Empty;
            string outputDir = ".tmp/";
            int timeout = 2000;
            bool verbose = false;

            #region Argument handling
            
            if (args.Length == 0) PrintUsage();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args.GetValue(i))
                {
                    case "-h":
                    case "--help":
                        PrintUsage();
                        break;

                    case "-i":
                    case "--input":
                        // next arg should be a file
                        if (i == args.Length)
                            Die("Need input file name");
                        inputFile = args.GetValue(++i).ToString();
                        break;

                    case "-n":
                    case "--hostname":
                        // next arg should be a file
                        if (i == args.Length)
                            Die("Need hostname");
                        inputHostName= args.GetValue(++i).ToString();
                        break;
                        
                    case "-o":
                    case "--output":
                        if (i == args.Length)
                            Die("Need output dir name");
                        outputDir = args.GetValue(++i).ToString();
                        break;

                    case "-t":
                    case "--timeout":
                        // next should be a file
                        if (i == args.Length)
                            Die("Specify timeout in milliseconds");
                        timeout = Int32.Parse(args.GetValue(++i).ToString());
                        break;

                    case "-v":
                    case "--verbose":
                        verbose = true;
                        break;

                    default:
                        Console.WriteLine("Unknown arg: {0}", args.GetValue(i));
                        break;
                }
            }
                        
            #endregion


            Ingestor ingestor = new Ingestor();

            #region prereqs

            if (!string.IsNullOrEmpty(inputFile))
            {
                // See if we can open and read the input file
                if (!File.Exists(inputFile))
                    Die("File does not exists: {0}", inputFile);

                using (var s = File.OpenRead(inputFile))
                {
                    if (!s.CanRead)
                        Die("Can't read file: {0}", inputFile);
                }
            }
            else
            {
                /// No input file specified
                if (string.IsNullOrEmpty(inputHostName))
                {
                    Die("I need either a --hostname or --inputfile");
                }
            }

            // See if the temp dir exists, if not make it 
            try
            {
                if (Directory.Exists(outputDir))
                {
                    // See if we have access to it to write files in
                    string tmpFile = $"{outputDir}/writable.txt";
                    File.WriteAllText(tmpFile, "hello world");
                    File.Delete(tmpFile);
                }
                else /// Create the dir
                {
                    Directory.CreateDirectory(outputDir);
                }
            }
            catch (IOException ex)
            {
                Die("Could not write to TMP dir {0}: {1}", new string[] { outputDir, ex.Message });
            }
            #endregion

            if (!string.IsNullOrEmpty(inputFile) && verbose)
                Console.WriteLine(" [i] reading {0}", inputFile);

            string[] hostnames = new string[] { };
            int counter = 0;
            int failedcounter = 0;

            if (!string.IsNullOrEmpty(inputFile))
            {
                hostnames = File.ReadAllLines(inputFile);
            }
            else
            {
                hostnames = new string[] { inputHostName };
            }

            foreach (string line in hostnames)
            {
                string hostname = line.Trim();

                #region Sanitize, normalize, prepend input
                if (string.IsNullOrEmpty(hostname))
                    continue;

                if (hostname.StartsWith("#"))
                    continue;

                hostname = hostname.ToLower();
                #endregion

                /// domain is good, retrieve the certs.
                if (ingestor.GetCert(hostname, out List<Cert> chain, timeout))
                {
                    if (chain.Count == 0)
                        continue;

                    /// Should put the data in {thumbprint}.json with it's children in it
                    string rootCaThumbFile = $"{outputDir}/{chain[0].thumbprint}.json";

                    Cert c = (Cert)chain[0];


                    if (File.Exists(rootCaThumbFile))
                    {
                        /// Add to existing file, we can overwrite c in mem

                        /// See if total chain exists; deserialize JSON
                        string s = File.ReadAllText(rootCaThumbFile);
                        c = JsonConvert.DeserializeObject<Cert>(s);

                        #region Collision check
                        // check if we have a cert with the same thumbprint, but another CN
                        if (c.subject != chain[0].subject)
                        {
                            Console.WriteLine("Collision for {0}", rootCaThumbFile);
                        }
                        #endregion
                    }

                    c.AddListOfChildren(chain.GetRange(1, chain.Count - 1));

                    try
                    {
                        // Leave our the ULL values to save some space
                        File.WriteAllText(rootCaThumbFile, 
                                            JsonConvert.SerializeObject(c, 
                                            Formatting.None, new JsonSerializerSettings { 
                                                NullValueHandling = NullValueHandling.Ignore
                                            }));
                    }
                    catch(IOException ex)
                    {
                        Console.WriteLine("Could not write file: {0}", ex.Message);
                        throw;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Bad stuff happened: {0}", ex.Message);
                        throw;
                    }

                    counter++;
                    
                    // ui
                    if (counter % 25 == 0)
                    {
                        Console.Write(".");
                        if (counter % 500 == 0)
                            Console.Write(" ({0}, {1}/{2})\n", hostname, counter, failedcounter);
                    }
                }
                else
                {
                    failedcounter++;
                }
            }
        }
    }
}
