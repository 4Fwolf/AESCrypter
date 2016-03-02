using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Management;
using System.Net.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace AESCrypter
{
    class Program
    {
        private static SymmetricAlgorithm alg;
        private static string _hash = "SHA512";
        private static int _keylen = 256;
        private static CipherMode _mode = CipherMode.CBC;
        private static string _iv = "aselrias38490a32";

        private static void Encrypt(string infile, string key)
        {
            alg = (SymmetricAlgorithm)RijndaelManaged.Create();

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(key, null);
            pdb.HashName = _hash; //будем использовать SHA512
            alg.KeySize = _keylen; //устанавливаем размер ключа
            alg.Key = pdb.GetBytes(_keylen >> 3); //получаем ключ из пароля
            alg.Mode = _mode; //используем режим CBC
            //alg.IV = new Byte[alg.BlockSize >> 3]; //и пустой инициализационный вектор
            alg.IV = GetBytes(_iv);

            Console.WriteLine("Hash:                {0}", pdb.HashName);
            Console.WriteLine("Key lenght:          {0}", alg.KeySize);
            Console.WriteLine("Encrypt key:         {0}", GetString(pdb.GetBytes(_keylen >> 3)));
            Console.WriteLine("Encrypt mode:        {0}", alg.Mode);
            Console.WriteLine("IV:                  {0}", GetString(alg.IV));

            ICryptoTransform tr = alg.CreateEncryptor(); //создаем encryptor

            FileStream instream = new FileStream(infile, FileMode.Open, FileAccess.Read, FileShare.Read);
            FileStream outstream = new FileStream(infile.Substring(0, infile.IndexOf('.')) + "_enc" + infile.Substring(infile.IndexOf('.')), FileMode.Create, FileAccess.Write, FileShare.None);
            
            outstream.Write(GetBytes(_iv + "\n"), 0, GetBytes(_iv + "\n").Length);
            
            int buflen = ((2 << 16) / alg.BlockSize) * alg.BlockSize;
            byte[] inbuf = new byte[buflen];
            byte[] outbuf = new byte[buflen];
            int len;
            while ((len = instream.Read(inbuf, 0, buflen)) == buflen)
            {
                int enclen = tr.TransformBlock(inbuf, 0, buflen, outbuf, 0); //собственно шифруем
                outstream.Write(outbuf, 0, enclen);
            }
            instream.Close();
            outbuf = tr.TransformFinalBlock(inbuf, 0, len); //шифруем финальный блок
            outstream.Write(outbuf, 0, outbuf.Length);
            outstream.Close();
            alg.Clear(); //осуществляем зачистку
        }
        private static void Decrypt(string infile, string key)
        {
            alg = (SymmetricAlgorithm)RijndaelManaged.Create(); //пример создания класса RijndaelManaged

            PasswordDeriveBytes pdb = new PasswordDeriveBytes(key, null); //класс, позволяющий генерировать ключи на базе паролей
            pdb.HashName = _hash; //будем использовать SHA512
            alg.KeySize = _keylen; //устанавливаем размер ключа
            alg.Key = pdb.GetBytes(_keylen >> 3); //получаем ключ из пароля
            alg.Mode = _mode; //используем режим CBC
            //alg.IV = new Byte[alg.BlockSize >> 3]; //и пустой инициализационный вектор
            alg.IV = GetBytes(_iv);

            Console.WriteLine("Hash:                {0}", pdb.HashName);
            Console.WriteLine("Key lenght:          {0}", alg.KeySize);
            Console.WriteLine("Encrypt key:         {0}", GetString(pdb.GetBytes(_keylen >> 3)));
            Console.WriteLine("Encrypt mode:        {0}", alg.Mode);
            Console.WriteLine("IV:                  {0}", GetString(alg.IV));

            ICryptoTransform tr = alg.CreateDecryptor(); //создаем decryptor

            FileStream instream = new FileStream(infile, FileMode.Open, FileAccess.Read, FileShare.Read);
            FileStream outstream = new FileStream(infile.Substring(0, infile.IndexOf('.')) + "_dec" + infile.Substring(infile.IndexOf('.')), FileMode.Create, FileAccess.Write, FileShare.None);

            instream.Read(GetBytes(_iv + "\n"), 0, GetBytes(_iv + "\n").Length);

            int buflen = ((2 << 16) / alg.BlockSize) * alg.BlockSize;
            byte[] inbuf = new byte[buflen];
            byte[] outbuf = new byte[buflen];
            int len;
            while ((len = instream.Read(inbuf, 0, buflen)) == buflen)
            {
                int enclen = tr.TransformBlock(inbuf, 0, buflen, outbuf, 0); //собственно шифруем
                outstream.Write(outbuf, 0, enclen);
            }
            instream.Close();
            outbuf = tr.TransformFinalBlock(inbuf, 0, len); //шифруем финальный блок
            outstream.Write(outbuf, 0, outbuf.Length);
            outstream.Close();
            alg.Clear(); //осуществляем зачистку
        }

        private static String GetString(byte[] bytes)
        {
            char[] chars = System.Text.Encoding.UTF8.GetChars(bytes);
            return new String(chars);
        }
        private static byte[] GetBytes(String str)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(str);
            //byte[] bytes = System.Text.Encoding.ASCII.GetBytes(str);
            return bytes;
        }

        public static void Main(string[] args)
        {
            string change;
            //String serial = "20071114173400000";
            string serial = string.Empty;
            
            insert:
            try
            {
                ManagementObjectSearcher theSearcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive WHERE InterfaceType='USB'");
                foreach (ManagementObject currentObject in theSearcher.Get())
                {
                    //Console.WriteLine(currentObject["InterfaceType"].ToString());
                    ManagementObject theSerialNumberObjectQuery = new ManagementObject("Win32_PhysicalMedia.Tag='" + currentObject["DeviceID"] + "'");
                    Console.WriteLine("Device serial:       {0}", theSerialNumberObjectQuery["SerialNumber"]);
                    serial = theSerialNumberObjectQuery["SerialNumber"].ToString();
                    break;
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

            //serial = "10071114173400000";

            checkKey:
            if (serial == string.Empty ||
                serial.Length < 10)
            {
                Console.WriteLine(" ");
                Console.WriteLine("Error: Key not found");
                Console.WriteLine("Note: Insert device with key or enter key manually!");
                Console.WriteLine("Note: Insert sevice : 1\n      Enter key manually : 2\n      Exit : any key");
                Console.WriteLine(" ");
                change = Console.ReadLine();
                if (change == "1") goto insert;
                else if (change == "2")
                {
                    serial = Console.ReadLine();
                    goto checkKey;
                }
                else return;
            }

            serial = serial + serial;
            byte[] tmp = GetBytes(serial);
            byte[] KEY = new byte[32];
            for (int i = 0; i < 32; ++i)
                KEY[i] = tmp[i];

            Console.WriteLine("Key:                 {0}", GetString(KEY));
            string filename = string.Empty;
            try
            {
                filename = args[0];
                Console.Write("File:                {0}", filename);
            }
            catch (Exception)
            {
                Console.Write("File:                ");
                filename = Console.ReadLine();
            }

            try
            {
                StreamReader tmpfile = new StreamReader(filename);
                string check = tmpfile.ReadLine();
                tmpfile.Close();
                if (check == _iv)
                {
                    Console.WriteLine("Mode:                Decrypt");
                    Console.WriteLine("Start time:          {0}", DateTime.Now.TimeOfDay);
                    Decrypt(filename, GetString(KEY));
                }
                else
                {
                    Console.WriteLine("Mode:                Encrypt");
                    Console.WriteLine("Start time:          {0}", DateTime.Now.TimeOfDay);
                    Encrypt(filename, GetString(KEY));
                }
            
            //change = Console.ReadLine();
            
                //if (change == "1") Encrypt(filename, GetString(KEY));
                //else if (change == "2") Decrypt(filename, GetString(KEY));
                //else return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(" ");
                Console.WriteLine("Error: {0}", ex.Message);
                Console.WriteLine(" ");
            }
            Console.WriteLine("End time:            {0}", DateTime.Now.TimeOfDay);
        }
    }
}
