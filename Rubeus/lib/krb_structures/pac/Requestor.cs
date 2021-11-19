using System.Security.Principal;

namespace Rubeus.Kerberos.PAC
{
    public class Requestor : PacInfoBuffer
    {

        public SecurityIdentifier RequestorSID { get; set; }

        public Requestor(PacInfoBufferType type)
        {
            this.Type = type;
        }

        public Requestor(SecurityIdentifier sid)
        {
            Type = PacInfoBufferType.Requestor;
            RequestorSID = sid;
        }

        public Requestor(string sid)
        {
            Type = PacInfoBufferType.Requestor;
            RequestorSID = new SecurityIdentifier(sid);
        }

        public Requestor(byte[] data) : base(data, PacInfoBufferType.Requestor)
        {
            Decode(data);
        }

        public override byte[] Encode()
        {
            byte[] binarySid = new byte[RequestorSID.BinaryLength];
            RequestorSID.GetBinaryForm(binarySid, 0);
            return binarySid;
        }

        protected override void Decode(byte[] data)
        {
            RequestorSID = new SecurityIdentifier(data, 0);
        }
    }
}
