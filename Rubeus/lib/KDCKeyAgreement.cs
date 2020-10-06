using Kerberos.NET.Crypto;
using System.Security.Cryptography;

namespace Rubeus {

    public class KDCKeyAgreement {

        public byte[] P { get { return Oakley.Group14.Prime; } }
        public byte[] G { get { return Oakley.Group14.Generator; } }
        public byte[] Q { get { return Oakley.Group14.Factor; } }
        public byte[] Y {get { return diffieHellman.PublicKey.PublicComponent; } }

        ManagedDiffieHellmanOakley14 diffieHellman = new ManagedDiffieHellmanOakley14();

        public KDCKeyAgreement() {                   
        }

        private static byte[] CalculateIntegrity(byte count, byte[] data) {

            byte[] input = new byte[data.Length + 1];
            input[0] = count;
            data.CopyTo(input, 1);

            using (SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider()) { 
                return sha1.ComputeHash(input);
            }            
        }

        private static byte[] kTruncate(int k, byte[] x) {

            int numberOfBytes = k;
            byte[] result = new byte[numberOfBytes];

            int count = 0;
            byte[] filler = CalculateIntegrity((byte)count, x);

            int position = 0;

            for (int i = 0; i < numberOfBytes; i++) {
                if (position < filler.Length) {
                    result[i] = filler[position];
                    position++;
                } else {
                    count++;
                    filler = CalculateIntegrity((byte)count, x);
                    position = 0;
                    result[i] = filler[position];
                    position++;
                }
            }

            return result;
        }
  
        public byte[] GenerateKey(byte[] otherPublicKey, byte[] clientNonce, byte[] serverNonce, int size) {

            DiffieHellmanKey diffieHellmanKey = new DiffieHellmanKey();
            diffieHellmanKey.PublicComponent = otherPublicKey;
            diffieHellmanKey.KeyLength = otherPublicKey.Length;
            diffieHellmanKey.Type = AsymmetricKeyType.Public;

            diffieHellman.ImportPartnerKey(diffieHellmanKey);
            byte[] sharedSecret = diffieHellman.GenerateAgreement();
        
            byte[] x = new byte[sharedSecret.Length + clientNonce.Length + serverNonce.Length];

            sharedSecret.CopyTo(x, 0);
            clientNonce.CopyTo(x, sharedSecret.Length);
            serverNonce.CopyTo(x, sharedSecret.Length + clientNonce.Length);                    
          
            return kTruncate(size, x);
        }
    }
}
