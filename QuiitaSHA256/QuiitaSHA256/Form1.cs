using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace QuiitaSHA256
{
    public partial class Form1 : Form
    {
        byte[] abc = Encoding.ASCII.GetBytes("abc");

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            using (SHA256NotManaged sha256 = SHA256NotManaged.Create())
            {
                //var plainText = textBox1.Text;
                //var encryptedText = sha256.ComputeHash(plainText);
                //textBox2.Text = encryptedText;

                TimeSpan elapsed = StopwatchEx.Context(() => { sha256.ComputeHash("abc"); }, 1000);
                Console.WriteLine($"自作: {elapsed.TotalMilliseconds}");
            }

            using (System.Security.Cryptography.SHA256 sha256_ = System.Security.Cryptography.SHA256.Create())
            {
                TimeSpan elapsed = StopwatchEx.Context(() => { sha256_.ComputeHash(abc); }, 1000);
                Console.WriteLine($"本家: {elapsed.TotalMilliseconds}");
            }
        }
    }
}
