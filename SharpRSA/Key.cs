using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.Serialization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;


namespace SharpRSA
{
    /// <summary>
    /// Wrapper KeyPair class, for the case when people generate keys locally.
    /// </summary>
    [DataContract]
    [Serializable]
    [DebuggerDisplay("{ToString()}")]
    public sealed class KeyPair
    {
        //After assignment, the keys cannot be touched.
        [DataMember]
        [JsonConverter(typeof(KeyJsonConverter))]
        public Key PrivateKey { get; private set; }
        [DataMember]
        [JsonConverter(typeof(KeyJsonConverter))]
        public Key PublicKey { get; private set; }

        public KeyPair(Key private__, Key public__)
        {
            PrivateKey = private__;
            PublicKey = public__;
        }

        /// <summary>
        /// Returns a keypair based on the calculated n and d values from RSA.
        /// </summary>
        /// <param name="n">The "n" value from RSA calculations.</param>
        /// <param name="d">The "d" value from RSA calculations.</param>
        /// <returns></returns>
        public static KeyPair Generate(BigInteger n, BigInteger d)
        {
            Key public_ = new Key(n, KeyType.PUBLIC);
            Key private_ = new Key(n, KeyType.PRIVATE, d);
            return new KeyPair(private_, public_);
        }

        public static KeyPair FromJson(string json)
        {
            JObject data = JObject.Parse(json);
            JToken privateKeyValue = data[nameof(PrivateKey)];
            JToken publicKeyValue = data[nameof(PublicKey)];

            if (privateKeyValue is null || publicKeyValue is null)
                throw new ArgumentException("Missing key");

            if (!Key.TryParseFromBase64(privateKeyValue?.Value<object>()?.ToString(), out Key privateKey))
                throw new InvalidCastException("Invalid privatekey");

            if (!Key.TryParseFromBase64(publicKeyValue?.Value<object>()?.ToString(), out Key publicKey))
                throw new InvalidCastException("Invalid publicKey");

            return new KeyPair(privateKey, publicKey);
        }
        public override string ToString() => ToJson();

        public string ToJson()
        {
            return JsonSerializer.Serialize<KeyPair>(this);
        }
    }

    /// <summary>
    /// Class to contain RSA key values for public and private keys. All values readonly and protected
    /// after construction, type set on construction.
    /// </summary>
    [DataContract(Name = "Key", Namespace = "SharpRSA")]
    [Serializable]
    [DebuggerDisplay("{Type} {ToString()}")]
    public class Key
    {
        //Hidden key constants, n and e are public key variables.
        [DataMember(Name = "n")]
        public BigInteger n { get; set; }
        [DataMember(Name = "e")]
        public int e = Constants.e;


        //Optional null variable D.
        //This should never be shared as a DataMember, by principle this should not be passed over a network.
        public readonly BigInteger d;

        //Variable for key type.
        [DataMember(Name = "type")]
        public KeyType Type { get; set; }

        //Constructor that sets values once, values then permanently unwriteable.
        public Key(BigInteger n_, KeyType type_, BigInteger d_)
        {
            //Catching edge cases for invalid input.
            if (type_ == KeyType.PRIVATE && d_ < 2) { throw new Exception("Constructed as private, but invalid d value provided."); }

            //Setting values.
            n = n_;
            Type = type_;
            d = d_;
        }

        //Overload constructor for key with no d value.
        public Key(BigInteger n_, KeyType type_)
        {
            //Catching edge cases for invalid input.
            if (type_ == KeyType.PRIVATE) { throw new Exception("Constructed as private, but no d value provided."); }

            //Setting values.
            n = n_;
            Type = type_;
        }
        public static bool TryParseFromBase64(string value, out Key key)
        {
            try
            {
                value = value.Replace("-----BEGIN RSA PRIVATE KEY-----", string.Empty)
                    .Replace("-----END RSA PRIVATE KEY-----", string.Empty)
                    .Replace("-----BEGIN RSA PUBLIC KEY-----", string.Empty)
                    .Replace("-----END RSA PUBLIC KEY-----", string.Empty).Trim();
                if (string.IsNullOrEmpty(value))
                {
                    key = null;
                    return false;
                }

                List<string> parts = new List<string>(2);
                StringBuilder sb = new StringBuilder();
                foreach (string line in value.Split("\n", StringSplitOptions.RemoveEmptyEntries))
                {
                    sb.Append(line.Trim());
                    if (line.Length < 76)
                    {
                        parts.Add(sb.ToString().Trim());
                        sb = new StringBuilder();
                    }
                }

                BigInteger n;
                if (parts.Count == 2)
                {
                    n = new BigInteger(Convert.FromBase64String(parts[0]));
                    BigInteger d = new BigInteger(Convert.FromBase64String(parts[1]));
                    key = new Key(n, KeyType.PRIVATE, d);
                    return true;

                }
                else if (parts.Count == 1)
                {
                    n = new BigInteger(Convert.FromBase64String(parts[0]));
                    key = new Key(n, KeyType.PUBLIC);
                    return true;
                }
            }
            catch (Exception ex) { Console.WriteLine(ex); }
            key = null;
            return false;
        }

        public override string ToString() => ToBase64();

        public string ToBase64()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN RSA {Type} KEY-----");
            sb.AppendLine(Convert.ToBase64String(this.n.ToByteArray(), Base64FormattingOptions.InsertLineBreaks)); //64?
            if (Type == KeyType.PRIVATE)
                sb.AppendLine(Convert.ToBase64String(this.d.ToByteArray(), Base64FormattingOptions.InsertLineBreaks)); //64?
            sb.AppendLine($"-----END RSA {Type} KEY-----");
            return sb.ToString();
        }
    }

    public enum KeyType
    {
        PUBLIC,
        PRIVATE
    }
}
