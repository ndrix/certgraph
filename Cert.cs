using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;
using System.Web;

namespace CertGraph.CLI.Models
{
    public class Cert
    {
        private string _thumbprint;
        private string _serial;

        [JsonProperty]
        public string name;

        [JsonProperty("ser")]
        public string serial
        {
            get { return _serial; }
            set { _serial = value.ToLower(); }
        }

        [JsonProperty("sub")]
        public string subject;

        [JsonProperty("exp")]
        public string expiry;

        [JsonProperty("thumb")]
        public string thumbprint
        {
            get { return _thumbprint;  }
            set { _thumbprint = value.ToLower(); }
        }

        [JsonProperty("iss")]
        public string issuer;

        [JsonProperty]
        public List<Cert> children;

        
        /// <summary>
        /// Recursively transforms an array into a parent->child structure.
        /// [a,b,c,d] turns into [a->[b->[c->[d]]]]
        /// </summary>
        /// <param name="chain"></param>
        /// <param name="maxDepth">maximum level of recursion</param>
        public void AddListOfChildren(List<Cert> chain, int maxDepth = 10)
        {
            /// Here, instead of doing recursion, we could also fail 
            /// early and simply check for a maximum supported chain (children)
            /// size.  But we'd rather have the first(maxDepth-1) elements, than an 
            /// empty one; in the case of a very large length.
            if (maxDepth-- < 1) return;

            /// fail quickly
            if (chain.Count == 0)
                return;

            /// it's our direct descendant in this hierarchy
            /// (child->grandchild->greatgrandchild->...]
            Cert newChild = chain.First<Cert>();

            /// we don't need to waste bytes on who the issuer is, we have 
            /// it in it's parent (this)
            newChild.issuer = null;

            /// If we already have our direct child?, load that for chainhead (so we load all its children too)
            if (this.children != null && this.children.Any(x => x.thumbprint.Equals(newChild.thumbprint)))
            {
                newChild = this.children.Find(x => x.thumbprint.Equals(newChild.thumbprint));
                int index = this.children.IndexOf(newChild);
                this.children.RemoveAt(index);
            }

            /// Check if we still have grandchildren, if so, add those.
            if (chain.Count > 1)
                newChild.AddListOfChildren(chain.GetRange(1, chain.Count - 1), maxDepth);

            /// this item has no children, so can make this its first child.
            if (this.children == null || this.children.Count == 0)
            {
                this.children = new List<Cert> { newChild };
            }
            else
            {
                /// add it to the current litter
                this.children.Add(newChild);
            }
        }
    }


    /// <summary>
    /// Store this here, dunno if it's very relevant
    /// </summary>
    public class Req
    {
        public string hostname { get; set; }
    }


}