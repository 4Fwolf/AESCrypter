using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Cryptography;

namespace AESCrypter
{
    /*public class USBSerialNumber
    {

        string _serialNumber;
        string _driveLetter;

        public string getSerialNumberFromDriveLetter(string driveLetter)
        {
            this._driveLetter = driveLetter.ToUpper();

            if (!this._driveLetter.Contains(":"))
            {
                this._driveLetter += ":";
            }

            matchDriveLetterWithSerial();

            return this._serialNumber;
        }

        private void matchDriveLetterWithSerial()
        {

            string[] diskArray;
            string driveNumber;
            string driveLetter;

            ManagementObjectSearcher searcher1 = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDiskToPartition");
            foreach (ManagementObject dm in searcher1.Get())
            {
                diskArray = null;
                driveLetter = getValueInQuotes(dm["Dependent"].ToString());
                diskArray = getValueInQuotes(dm["Antecedent"].ToString()).Split(',');
                driveNumber = diskArray[0].Remove(0, 6).Trim();
                if (driveLetter == this._driveLetter)
                {
                    ManagementObjectSearcher disks = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
                    foreach (ManagementObject disk in disks.Get())
                    {

                        if (disk["Name"].ToString() == ("\\\\.\\PHYSICALDRIVE" + driveNumber) & disk["InterfaceType"].ToString() == "USB")
                        {
                            this._serialNumber = parseSerialFromDeviceID(disk["PNPDeviceID"].ToString());
                        }
                    }
                }
            }
        }

        private string parseSerialFromDeviceID(string deviceId)
        {
            string[] splitDeviceId = deviceId.Split('\\');
            string[] serialArray;
            string serial;
            int arrayLen = splitDeviceId.Length - 1;

            serialArray = splitDeviceId[arrayLen].Split('&');
            serial = serialArray[0];

            return serial;
        }

        private string getValueInQuotes(string inValue)
        {
            string parsedValue = "";

            int posFoundStart = 0;
            int posFoundEnd = 0;

            posFoundStart = inValue.IndexOf("\"");
            posFoundEnd = inValue.IndexOf("\"", posFoundStart + 1);

            parsedValue = inValue.Substring(posFoundStart + 1, (posFoundEnd - posFoundStart) - 1);

            return parsedValue;
        }

    }*/

    class AesCrypter
    {
        #region Crypt Settings
        private static SymmetricAlgorithm _alg;
        private static readonly string _hash = "SHA512";
        private static readonly int _keylen = 256;
        private static readonly CipherMode _mode = CipherMode.CBC;
        private static readonly string _iv = "aselrias38490a32";
        #endregion

        private static void Encrypt(string infile, string key)
        {
            string outfile = infile.Substring(0, infile.IndexOf('.')) + "_enc" + infile.Substring(infile.IndexOf('.'));
            _alg = (SymmetricAlgorithm)RijndaelManaged.Create();

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(key, null) {HashName = _hash};
            _alg.KeySize = _keylen;
            _alg.Key = pdb.GetBytes(_keylen >> 3);
            _alg.Mode = _mode;
            _alg.IV = GetBytes(_iv);

            Console.WriteLine("Hash:                {0}", pdb.HashName);
            Console.WriteLine("Key lenght:          {0}", _alg.KeySize);
            Console.WriteLine("Encrypt key:         {0}", GetString(pdb.GetBytes(_keylen >> 3)));
            Console.WriteLine("Encrypt mode:        {0}", _alg.Mode);
            Console.WriteLine("IV:                  {0}", GetString(_alg.IV));

            ICryptoTransform tr = _alg.CreateEncryptor();

            FileStream instream = new FileStream(infile, FileMode.Open, FileAccess.Read, FileShare.Read);
            FileStream outstream = new FileStream(outfile, FileMode.Create, FileAccess.Write, FileShare.None);
            
            outstream.Write(GetBytes(_iv + "\n"), 0, GetBytes(_iv + "\n").Length);
            
            int buflen = ((2 << 16) / _alg.BlockSize) * _alg.BlockSize;
            byte[] inbuf = new byte[buflen];
            byte[] outbuf = new byte[buflen];
            int len;
            while ((len = instream.Read(inbuf, 0, buflen)) == buflen)
            {
                int enclen = tr.TransformBlock(inbuf, 0, buflen, outbuf, 0);
                outstream.Write(outbuf, 0, enclen);
            }
            instream.Close();
            outbuf = tr.TransformFinalBlock(inbuf, 0, len);
            outstream.Write(outbuf, 0, outbuf.Length);
            outstream.Close();
            _alg.Clear();
        }
        private static void Decrypt(string infile, string key)
        {
            string outfile = string.Empty;
            if (infile.Contains("_enc."))
                outfile = infile.Substring(0, infile.IndexOf('_')) + "_dec" + infile.Substring(infile.IndexOf('.'));
            else
                outfile = infile.Substring(0, infile.IndexOf('.')) + "_dec" + infile.Substring(infile.IndexOf('.'));
           
            _alg = (SymmetricAlgorithm)RijndaelManaged.Create();

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(key, null) {HashName = _hash};
            _alg.KeySize = _keylen;
            _alg.Key = pdb.GetBytes(_keylen >> 3);
            _alg.Mode = _mode;
            _alg.IV = GetBytes(_iv);

            Console.WriteLine("Hash:                {0}", pdb.HashName);
            Console.WriteLine("Key lenght:          {0}", _alg.KeySize);
            Console.WriteLine("Encrypt key:         {0}", GetString(pdb.GetBytes(_keylen >> 3)));
            Console.WriteLine("Encrypt mode:        {0}", _alg.Mode);
            Console.WriteLine("IV:                  {0}", GetString(_alg.IV));

            ICryptoTransform tr = _alg.CreateDecryptor();

            FileStream instream = new FileStream(infile, FileMode.Open, FileAccess.Read, FileShare.Read);
            FileStream outstream = new FileStream(outfile, FileMode.Create, FileAccess.Write, FileShare.None);

            instream.Read(GetBytes(_iv + "\n"), 0, GetBytes(_iv + "\n").Length);

            int buflen = ((2 << 16) / _alg.BlockSize) * _alg.BlockSize;
            byte[] inbuf = new byte[buflen];
            byte[] outbuf = new byte[buflen];
            int len;
            while ((len = instream.Read(inbuf, 0, buflen)) == buflen)
            {
                int enclen = tr.TransformBlock(inbuf, 0, buflen, outbuf, 0);
                outstream.Write(outbuf, 0, enclen);
            }
            instream.Close();
            outbuf = tr.TransformFinalBlock(inbuf, 0, len);
            outstream.Write(outbuf, 0, outbuf.Length);
            outstream.Close();
            _alg.Clear();
        }

        private static string GetString(byte[] bytes)
        {
            char[] chars = System.Text.Encoding.UTF8.GetChars(bytes);
            return new string(chars);
        }
        private static byte[] GetBytes(string str)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(str);
            //byte[] bytes = System.Text.Encoding.ASCII.GetBytes(str);
            return bytes;
        }

        private static string GetValueInQuotes(string inValue)
        {
            var posFoundStart = inValue.IndexOf("\"", StringComparison.Ordinal);
            var posFoundEnd = inValue.IndexOf("\"", posFoundStart + 1, StringComparison.Ordinal);

            var parsedValue = inValue.Substring(posFoundStart + 1, (posFoundEnd - posFoundStart) - 1);

            return parsedValue;
        }
        private static string ParseSerialFromDeviceId(string deviceId)
        {
            string[] splitDeviceId = deviceId.Split('\\');
            int arrayLen = splitDeviceId.Length - 1;

            var serialArray = splitDeviceId[arrayLen].Split('&');
            var serial = serialArray[0];

            return serial;
        }

        public static void Main(string[] args)
        {
            //String serial = "20071114173400000";
            string serial = string.Empty;

            #region Serial Init
        insert:
            try
            {
                ManagementObjectSearcher searcher1 = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDiskToPartition");
                foreach (var o in searcher1.Get())
                {
                    var dm = (ManagementObject) o;
                    serial = GetValueInQuotes(dm["Dependent"].ToString());
                    var diskArray = GetValueInQuotes(dm["Antecedent"].ToString()).Split(',');
                    var driveNumber = diskArray[0].Remove(0, 6).Trim();
                        ManagementObjectSearcher disks = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
                        foreach (var disk in disks.Get().Cast<ManagementObject>().Where(disk => disk["Name"].ToString() == ("\\\\.\\PHYSICALDRIVE" + driveNumber) & disk["InterfaceType"].ToString() == "USB"))
                        {
                            serial = ParseSerialFromDeviceId(disk["PNPDeviceID"].ToString());
                        }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(" ");
                Console.WriteLine("Error: {0}", ex.Message);
                Console.WriteLine(" ");
                Console.ReadLine();
                return;
            }
            #endregion

            #region Key check
        checkKey:
            if (serial != null && (serial == string.Empty ||
                                   serial.Length < 10))
            {
                Console.WriteLine(" ");
                Console.WriteLine("Error: Key not found");
                Console.WriteLine("Note: Insert device with key or enter key manually!");
                Console.WriteLine("Note: Insert sevice : 1\n      Enter key manually : 2\n      Exit : any key");
                Console.WriteLine(" ");
                var change = Console.ReadLine();
                if (change == "1") goto insert;
                if (change == "2")
                {
                    serial = Console.ReadLine();
                    goto checkKey;
                }
                return;
            }
            Console.WriteLine("Key:                 {0}", serial);
            #endregion

            #region File
            string filename;
            try
            {
                filename = args[0];
                Console.Write("File:                {0}\n", filename);
            }
            catch (Exception)
            {
                Console.Write("File:                ");
                filename = Console.ReadLine();
            }
            #endregion

            try
            {
                if (filename != null)
                {
                    StreamReader tmpfile = new StreamReader(filename);
                    string check = tmpfile.ReadLine();
                    tmpfile.Close();
                    if (check == _iv)
                    {
                        Console.WriteLine("Mode:                Decrypt");
                        Console.WriteLine("Start time:          {0}", DateTime.Now.TimeOfDay);
                        //Decrypt(filename, GetString(KEY));
                        Decrypt(filename, serial);
                    }
                    else
                    {
                        Console.WriteLine("Mode:                Encrypt");
                        Console.WriteLine("Start time:          {0}", DateTime.Now.TimeOfDay);
                        //Encrypt(filename, GetString(KEY));
                        Encrypt(filename, serial);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(" ");
                Console.WriteLine("Error: {0}", ex.Message);
                Console.WriteLine(" ");
                Console.ReadLine();
            }
            Console.WriteLine("End time:            {0}", DateTime.Now.TimeOfDay);
        }
    }
}
