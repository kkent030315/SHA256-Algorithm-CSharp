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
            var plainText = textBox1.Text;

            using (SHA256NotManaged sha256 = SHA256NotManaged.Create())
            {
                var encryptedText = sha256.ComputeHash(plainText);
                textBox2.Text = encryptedText;

                //TimeSpan elapsed = StopwatchEx.Context(() => { sha256.ComputeHash("abc"); }, 1000);
                //Console.WriteLine($"自作: {elapsed.TotalMilliseconds}");
            }

            using (System.Security.Cryptography.SHA256 sha256_ = System.Security.Cryptography.SHA256.Create())
            {
                var sha256bytes = sha256_.ComputeHash(Encoding.ASCII.GetBytes(plainText));
                var encryptedSha256Managed = string.Join("", sha256bytes.Select(v => $"{v:X2}"));

                Console.Write("本家Bytes: ");
                PrintArray(sha256bytes);

                textBox3.Text = encryptedSha256Managed.ToLower();

                //TimeSpan elapsed = StopwatchEx.Context(() => { sha256_.ComputeHash(abc); }, 1000);
                //Console.WriteLine($"本家: {elapsed.TotalMilliseconds}");
            }

            if(!string.IsNullOrEmpty(textBox2.Text) && !string.IsNullOrEmpty(textBox3.Text))
            {
                if(string.Equals(textBox2.Text, textBox3.Text, StringComparison.OrdinalIgnoreCase))
                {
                    label1.Text = "OK";
                }
                else
                {
                    label1.Text = "Mismatch";
                }
            }
        }

        private void PrintArray<T>(IList<T> source)
        {
            //int[] hoge = { 0, 1, 2, 3, 4 }; -> [ 0, 1, 2, 3, 4 ] (Output)
            Console.WriteLine(string.Format("({0})", source.Count) + "[ " + string.Join(", ", source) + " ]");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var input_string = textBox4.Text;
            var input_x16 = textBox5.Text;
            var input_x2 = textBox6.Text;

            if(!string.IsNullOrEmpty(input_string))
            {
                textBox5.Text = Convert.ToString(Encoding.ASCII.GetBytes(input_string)[0], 16);
                textBox6.Text = Convert.ToString(Encoding.ASCII.GetBytes(input_string)[0], 2);
            }
        }
    }
}
