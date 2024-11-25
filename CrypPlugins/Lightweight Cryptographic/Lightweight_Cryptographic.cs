/*
   Copyright CrypTool 2 Team <ct2contact@cryptool.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
using CrypTool.PluginBase;
using CrypTool.PluginBase.Miscellaneous;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Cryptography;
using System.Windows.Controls;

namespace CrypTool.Plugins.Lightweight_Cryptographic
{
    // HOWTO: Plugin developer HowTo can be found here: https://github.com/CrypToolProject/CrypTool-2/wiki/Developer-HowTo

    // HOWTO: Change author name, email address, organization and URL.
    [Author("Author", "author@example.com", "", "https://www.cryptool.org")]
    // HOWTO: Change plugin caption (title to appear in CT2) and tooltip.
    // You can (and should) provide a user documentation as XML file and an own icon.
    [PluginInfo("Lightweight Cryptographic", "A lightweight encryption and decryption method.", "Lightweight_Cryptographic/userdoc.xml", new[] { "CrypWin/images/default.png" })]
    // HOWTO: Change category to one that fits to your plugin. Multiple categories are allowed.
    [ComponentCategory(ComponentCategory.CiphersModernAsymmetric)]
    public class Lightweight_Cryptographic : ICrypComponent
    {
        #region Private Variables
        // HOWTO: You need to adapt the settings class as well, see the corresponding file.
        private readonly Lightweight_CryptographicSettings settings = new Lightweight_CryptographicSettings();

        private const int KEY_SIZE = 16;     // 密钥长度：128位
        private const int BLOCK_SIZE = 16;   // 块大小：128位
        #endregion

        #region Data Properties

        /// <summary>
        /// HOWTO: Input interface to read the input data. 
        /// You can add more input properties of other type if needed.
        /// </summary>
        [PropertyInfo(Direction.InputData, "Input byte", "Input tooltip description")]
        public byte[] Input
        {
            get;
            set;
        }

        [PropertyInfo(Direction.InputData, "Key byte", "Input tooltip description")]
        public string Key
        {
            get;
            set;
        }

        /// <summary>
        /// HOWTO: Output interface to write the output data.
        /// You can add more output properties ot other type if needed.
        /// </summary>
        [PropertyInfo(Direction.OutputData, "Output byte", "Output tooltip description")]
        public byte[] Output
        {
            get;
            set;
        }

        #endregion

        #region IPlugin Members

        /// <summary>
        /// Provide plugin-related parameters (per instance) or return null.
        /// </summary>
        public ISettings Settings
        {
            get { return settings; }
        }

        /// <summary>
        /// Provide custom presentation to visualize the execution or return null.
        /// </summary>
        public UserControl Presentation
        {
            get { return null; }
        }

        /// <summary>
        /// Called once when workflow execution starts.
        /// </summary>
        public void PreExecution()
        {
        }

        /// <summary>
        /// Called every time this plugin is run in the workflow execution.
        /// </summary>
        public void Execute()
        {
            ProgressChanged(0, 1);
            try
            {
                switch (settings.Action)
                {
                    case ActionType.Encrypt:
                        {
                            // data
                            //string message = "Hello World!";
                            //byte[] data = System.Text.Encoding.UTF8.GetBytes(Input);

                            // password
                            //string password = "MyPassword123";
                            byte[] key = DeriveKeyFromPassword(Key);

                            // encrypt
                            byte[] encrypted = Encrypt(Input, key);

                            Output = encrypted;
                            OnPropertyChanged(nameof(Output));
                        }
                        break;

                    case ActionType.Decrypt:
                        {
                            // decrypt
                            // password
                            //string password = "MyPassword123";
                            byte[] key = DeriveKeyFromPassword(Key);

                            byte[] decrypted = Decrypt(Input, key);

                            Output = decrypted;
                            OnPropertyChanged(nameof(Output));
                        }
                        //string decryptedMessage = System.Text.Encoding.UTF8.GetString(decrypted);
                        break;
                    default:
                        break;
                }

            }
            catch (Exception ex)
            {
                GuiLogMessage(string.Format("Error: {0}", ex.Message), NotificationLevel.Error);
            }

            ProgressChanged(1, 1);
        }


        #region simple hash function
        public byte[] SimpleHash(byte[] data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            // initial hash
            uint hash1 = 0x6a09e667;
            uint hash2 = 0xbb67ae85;
            uint hash3 = 0x3c6ef372;
            uint hash4 = 0xa54ff53a;

            // for every byte
            for (int i = 0; i < data.Length; i++)
            {
                hash1 = (hash1 << 7) ^ data[i];
                hash2 = (hash2 << 11) ^ data[i];
                hash3 = RotateLeft(hash3, 17) ^ data[i];
                hash4 = RotateLeft(hash4, 5) ^ data[i];

                // mix hash
                uint temp = hash1;
                hash1 = hash2;
                hash2 = hash3;
                hash3 = hash4;
                hash4 = temp;
            }

            // cobine hash
            byte[] result = new byte[16];
            BitConverter.GetBytes(hash1).CopyTo(result, 0);
            BitConverter.GetBytes(hash2).CopyTo(result, 4);
            BitConverter.GetBytes(hash3).CopyTo(result, 8);
            BitConverter.GetBytes(hash4).CopyTo(result, 12);

            return result;
        }
        #endregion

        #region generakey
        public byte[] GenerateKey()
        {
            byte[] key = new byte[KEY_SIZE];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(key);
            }
            return key;
        }

        public byte[] DeriveKeyFromPassword(string password)
        {
            return SimpleHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
        #endregion

        #region encrypt and decrypt
        public byte[] Encrypt(byte[] data, byte[] key)
        {
            if (data == null || key == null)
                throw new ArgumentNullException();

            if (key.Length != KEY_SIZE)
                throw new ArgumentException("Invalid key size");

            // add random IV
            byte[] iv = new byte[BLOCK_SIZE];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(iv);
            }

            // pad
            int paddedLength = ((data.Length + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
            byte[] result = new byte[BLOCK_SIZE + paddedLength];

            // copy IV and data
            Buffer.BlockCopy(iv, 0, result, 0, BLOCK_SIZE);
            Buffer.BlockCopy(data, 0, result, BLOCK_SIZE, data.Length);

            // encrypt
            for (int i = BLOCK_SIZE; i < result.Length; i += BLOCK_SIZE)
            {
                byte[] block = new byte[BLOCK_SIZE];
                Buffer.BlockCopy(result, i, block, 0, Math.Min(BLOCK_SIZE, result.Length - i));

                // XOR with befroere block
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    block[j] ^= result[i - BLOCK_SIZE + j];
                }

                // encrypt
                EncryptBlock(block, key);

                // result
                Buffer.BlockCopy(block, 0, result, i, BLOCK_SIZE);
            }

            return result;
        }

        public byte[] Decrypt(byte[] data, byte[] key)
        {
            if (data == null || key == null)
                throw new ArgumentNullException();

            if (key.Length != KEY_SIZE || data.Length < BLOCK_SIZE * 2)
                throw new ArgumentException("Invalid input");

            byte[] result = new byte[data.Length - BLOCK_SIZE];
            Buffer.BlockCopy(data, BLOCK_SIZE, result, 0, result.Length);

            // decrypt
            for (int i = 0; i < result.Length; i += BLOCK_SIZE)
            {
                byte[] block = new byte[BLOCK_SIZE];
                Buffer.BlockCopy(result, i, block, 0, Math.Min(BLOCK_SIZE, result.Length - i));

                // decrypt block
                DecryptBlock(block, key);

                // XOR with before block
                for (int j = 0; j < BLOCK_SIZE; j++)
                {
                    block[j] ^= data[i + j];
                }

                // result
                Buffer.BlockCopy(block, 0, result, i, BLOCK_SIZE);
            }

            // out pad
            int originalLength = result.Length;
            while (originalLength > 0 && result[originalLength - 1] == 0)
            {
                originalLength--;
            }

            byte[] finalResult = new byte[originalLength];
            Buffer.BlockCopy(result, 0, finalResult, 0, originalLength);
            return finalResult;
        }

        private void EncryptBlock(byte[] block, byte[] key)
        {
            // simple block encrypt
            for (int i = 0; i < BLOCK_SIZE; i++)
            {
                // XOR with key
                block[i] ^= key[i % key.Length];

                // Simple substitution
                block[i] = (byte)((block[i] << 4) | (block[i] >> 4));

                // Add round constant
                block[i] += (byte)(i + 1);
            }

            // Block mixing
            for (int round = 0; round < 4; round++)
            {
                byte temp = block[0];
                for (int i = 0; i < BLOCK_SIZE - 1; i++)
                {
                    block[i] = block[i + 1];
                }
                block[BLOCK_SIZE - 1] = temp;
            }
        }

        private void DecryptBlock(byte[] block, byte[] key)
        {
            // mix
            for (int round = 0; round < 4; round++)
            {
                byte temp = block[BLOCK_SIZE - 1];
                for (int i = BLOCK_SIZE - 1; i > 0; i--)
                {
                    block[i] = block[i - 1];
                }
                block[0] = temp;
            }

            // decrypt block
            for (int i = BLOCK_SIZE - 1; i >= 0; i--)
            {
                block[i] -= (byte)(i + 1);
                block[i] = (byte)((block[i] >> 4) | (block[i] << 4));
                block[i] ^= key[i % key.Length];
            }
        }

        private uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }
        #endregion


        /// <summary>
        /// Called once after workflow execution has stopped.
        /// </summary>
        public void PostExecution()
        {
        }

        /// <summary>
        /// Triggered time when user clicks stop button.
        /// Shall abort long-running execution.
        /// </summary>
        public void Stop()
        {
        }

        /// <summary>
        /// Called once when plugin is loaded into editor workspace.
        /// </summary>
        public void Initialize()
        {
        }

        /// <summary>
        /// Called once when plugin is removed from editor workspace.
        /// </summary>
        public void Dispose()
        {
        }

        #endregion

        #region Event Handling

        public event StatusChangedEventHandler OnPluginStatusChanged;

        public event GuiLogNotificationEventHandler OnGuiLogNotificationOccured;

        public event PluginProgressChangedEventHandler OnPluginProgressChanged;

        public event PropertyChangedEventHandler PropertyChanged;

        private void GuiLogMessage(string message, NotificationLevel logLevel)
        {
            EventsHelper.GuiLogMessage(OnGuiLogNotificationOccured, this, new GuiLogEventArgs(message, this, logLevel));
        }

        private void OnPropertyChanged(string name)
        {
            EventsHelper.PropertyChanged(PropertyChanged, this, new PropertyChangedEventArgs(name));
        }

        private void ProgressChanged(double value, double max)
        {
            EventsHelper.ProgressChanged(OnPluginProgressChanged, this, new PluginProgressEventArgs(value, max));
        }

        #endregion
    }
}
