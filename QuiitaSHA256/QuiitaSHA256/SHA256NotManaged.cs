using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuiitaSHA256
{
    public sealed class SHA256NotManaged : IDisposable
    {
        /// <summary>
        /// 初期ハッシュ
        /// </summary>
        private uint[] initial_hash = 
        { 
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 
        };

        /// <summary>
        /// Kと呼ばれる定数
        /// </summary>
        private readonly uint[] const_k = new uint[64] 
        {
            0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 
            0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
            0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 
            0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
            0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 
            0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
            0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 
            0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
            0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 
            0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
            0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 
            0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
            0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 
            0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
            0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 
            0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        };

        /// <summary>
        /// コンストラクタ
        /// </summary>
        public SHA256NotManaged() { }

        /// <summary>
        /// 静的コンストラクタ
        /// </summary>
        static SHA256NotManaged() { }

        /// <summary>
        /// インスタンスを生成します。
        /// </summary>
        /// <returns>インスタンス</returns>
        public static SHA256NotManaged Create()
        {
            return new SHA256NotManaged();
        }

        /// <summary>
        /// SHA256ハッシュを生成します。
        /// </summary>
        /// <param name="plainText">暗号化したい文字列</param>
        /// <returns>暗号化された文字列</returns>
        public string ComputeHash(string plainText)
        {
            var p = Padding(plainText);

            var block_list = Parse(p);
            var s = new uint[8];
            Array.Copy(initial_hash, s, initial_hash.Length);

#if DEBUG
            Console.WriteLine("↓初期ハッシュ");
            PrintArray(s); //(8)[ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 ]
#endif

            //ブロックリストの中のブロックにスコープを当てる
            foreach (var block in block_list)
            {
                Console.Write("BLOCK: ");
                PrintArray(block);
                Console.WriteLine(string.Join("", block));

                var pair = MakePair(s);
                var expanded_block = ExpandBlock(block);

                for (int n = 0; n < 64; ++n)
                {
                    var CH = Ch(pair["e"], pair["f"], pair["g"]);
                    var MAJ = Maj(pair["a"], pair["b"], pair["c"]);
                    var SIG0 = Sigma0(pair["a"]);
                    var SIG1 = Sigma1(pair["e"]);

                    var WJ_KJ = (const_k[n] + expanded_block[n]);
                    var T1_TEMP = (pair["h"] + WJ_KJ + CH);
                    var T1 = (T1_TEMP + SIG1);
                    var T2 = (SIG0 + MAJ);

                    pair["h"] = pair["g"];
                    pair["g"] = pair["f"];
                    pair["f"] = pair["e"];
                    pair["e"] = (pair["d"] + T1);
                    pair["d"] = pair["c"];
                    pair["c"] = pair["b"];
                    pair["b"] = pair["a"];
                    pair["a"] = (T1 + T2);
                }

                s[0] = (pair["a"] + s[0]);
                s[1] = (pair["b"] + s[1]);
                s[2] = (pair["c"] + s[2]);
                s[3] = (pair["d"] + s[3]);
                s[4] = (pair["e"] + s[4]);
                s[5] = (pair["f"] + s[5]);
                s[6] = (pair["g"] + s[6]);
                s[7] = (pair["h"] + s[7]);

#if DEBUG
                PrintArray(s); //[3128432319, 2399260650, 1094795486, 1571693091, 2953011619, 2518121116, 3021012833, 4060091821]
#endif
            }

#if DEBUG
            Console.Write("RESULT: ");
            PrintArray(s);
#endif

            return MakeHash(s);
        }

        /// <summary>
        /// ブロックを処理します。
        /// </summary>
        /// <param name="block">64バイトの2進数ブロック配列</param>
        /// <returns>処理された2進数ブロック配列</returns>
        private uint[] ExpandBlock(uint[] block)
        {
            uint[] result = { };

            for(int x = 0; x < 16; x++)
            {
                //例
                //バイナリ -> ヘックスデミカル -> uint OR バイナリ -> demical
                //↓チャンクバイナリ 01100001011000100110001110000000 は ヘックスデミカル 0x61626380 である.
                //CHUNK: [ 32 ] [0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
                //= 0x61626380 したがって uint は 1633837952

                //コピー先のチャンク配列
                uint[] chunk_array = new uint[32];
                //ブロックの x*32 から 32byte先までをコピー
                Array.Copy(block, x*32, chunk_array, 0, 32);
                //バイナリに変換
                var chunk_binary_str = ToBinary(chunk_array);

#if DEBUG
                //Console.Write($"チャンク [{x*32}-{(x*32)+32}] ");
                Console.Write($"チャンク [{((x * 32) + 32).ToString().PadLeft(3, ' ')}] ");
                Console.Write(chunk_binary_str);
#endif

                var chunk_decimal = Convert.ToUInt32(chunk_binary_str, 2);

#if DEBUG
                Console.Write(" : " + chunk_decimal + "\n");
#endif

                SelfAppend(ref result, chunk_decimal);
            }

            for(int y = 16; y < 64; y++)
            {
                var T1 = Sub0(result[y - 15]) + result[y - 16];
                var T2 = T1 + result[y - 7];
                var T3 = T2 + Sub1(result[y - 2]);

                SelfAppend(ref result, T3);
            }

#if DEBUG
            PrintArray(result);
#endif

            return result;
        }

        /// <summary>
        /// バイナリをデシマル Integer に変換します。
        /// </summary>
        /// <param name="binary_str">バイナリ</param>
        /// <returns>デシマル Integer</returns>
        private int BinaryToDecimal(string binary_str)
        {
            char[] binary_char_array = binary_str.ToCharArray();
            Array.Reverse(binary_char_array);
            int result = 0;

            for (int i = 0; i < binary_char_array.Length; i++)
            {
                if (binary_char_array[i] == '1')
                {
                    if (i == 0)
                    {
                        result += 1;
                    }
                    else
                    {
                        result += (int)Math.Pow(2, i);
                    }
                }

            }

            return result;
        }

        /// <summary>
        /// チャンクをバイナリに変換します。
        /// </summary>
        /// <param name="chunk"></param>
        /// <returns>変換されたバイナリ</returns>
        private string ToBinary(uint[] chunk)
        {
            string result = string.Empty;

            foreach (var n in chunk)
            {
                result += n.ToString();
            }

            //ArgumentOutOfRangeException
            //chunk.Select((v) => result += v.ToString());

            return result;
        }

        /// <summary>
        /// 2進数を16進数の文字列に変換します。
        /// </summary>
        /// <param name="s">変換したい2進数配列</param>
        /// <returns>変換された文字列</returns>
        private string MakeHash(uint[] s)
        {
            var s_byte_array = s.SelectMany((v) => BitConverter.GetBytes(v).Reverse()).ToArray();
            var result_str = string.Join("", s_byte_array.Select(v => $"{v:X2}"));
            return result_str.ToLower();
        }

        /// <summary>
        /// 計算をより楽に、分かりやすくするためにStringとのペアを生成します。
        /// </summary>
        /// <param name="hash">ペアと対になる2進数配列</param>
        /// <returns>ペアを格納したディクショナリ</returns>
        private Dictionary<string, uint> MakePair(uint[] hash)
        {
            var dictionary = new Dictionary<string, uint>();
            dictionary.Add("a", hash[0]);
            dictionary.Add("b", hash[1]);
            dictionary.Add("c", hash[2]);
            dictionary.Add("d", hash[3]);
            dictionary.Add("e", hash[4]);
            dictionary.Add("f", hash[5]);
            dictionary.Add("g", hash[6]);
            dictionary.Add("h", hash[7]);

            return dictionary;
        }

        /// <summary>
        /// パディングされた配列を512バイトのブロック長に分割します。
        /// </summary>
        /// <param name="plain_bits">分割する2進数配列</param>
        /// <returns>分割された2進数ブロック一覧を格納したジャグ配列</returns>
        private List<uint[]> Parse(uint[] plain_bits)
        {
            var result = new List<uint[]>();
            const int BLOCK_SIZE = 512;
            var length = plain_bits.Length;
            var num_blocks = length / BLOCK_SIZE;

            for(int n = 0; n < num_blocks; n++)
            {
                var block = new uint[BLOCK_SIZE];
                Array.Copy(plain_bits, n * BLOCK_SIZE, block, 0, BLOCK_SIZE);
                
                //ブロックリストに追加
                result.Add(block);

#if DEBUG
                Console.Write("ParsedBlock: ");
                PrintArray(block);
#endif
            }

            return result;
        }

        /// <summary>
        /// パディングと呼ばれる、空埋め処理を行います。
        /// </summary>
        /// <param name="plain_text">パディングする2進数配列</param>
        /// <returns>パディングされた2進数配列</returns>
        private uint[] Padding(string plain_text)
        {
            var plain_bits = ToUInt32Array(plain_text);
            var length = plain_bits.Length;
            var k = CalculateK(plain_bits);

            //処理する値を保持するバッファ
            uint[] buf = { };

            buf = Extend<uint>(plain_bits, 1);

            for(int r = 0; r < k; r++)
            {
                SelfAppend(ref buf, 0u);
            }

#if DEBUG
            Console.WriteLine("↓PrintArray");
            PrintArray(buf);
#endif

            var bytStr = Convert.ToString(length, 2);

            //64桁右寄せゼロ埋め
            //0000000000000000000000000000000000000000000000000000000000011000
            bytStr = bytStr.ToString().PadLeft(64, '0');

#if DEBUG
            Console.WriteLine("After PadLeft: " + bytStr.Length);
            Console.WriteLine(bytStr.Length + " | " + bytStr);
#endif

            //↑で得た64桁の数列を配列に変換
            //(64)[ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0 ]
            uint[] bytStr_array = { };
            for(int x = 0; x <= 63; x++)
            {
                var num_str = bytStr.Substring(x, 1);
                var num = uint.Parse(num_str);
                SelfAppend(ref bytStr_array, num);
#if DEBUG
                Console.Write("BytStrArr: ");
                PrintArray(bytStr_array);
#endif
            }

            //位取り バッファにAppend
            foreach(var b in bytStr_array)
            {
                SelfAppend(ref buf, b);
            }

#if DEBUG
            //ブロックサイズはパディング後512である
            //Assert(buf.Length != 512)
            PrintArray(buf); //512
#endif

            return buf;
        }

        /// <summary>
        /// 与えられた配列から定数Kを算出します。
        /// </summary>
        /// <param name="plain_bits">算出された数</param>
        /// <returns>定数K</returns>
        private uint CalculateK(uint[] plain_bits)
        {
            uint k = 0;
            var length = plain_bits.Length;

            while ((length + 1 + k) % 512 != 448)
            {
                k += 1;
            }

            return k;
        }

        /// <summary>
        /// Stringを2進数に変換します。
        /// </summary>
        /// <param name="plain_text">暗号化する文字列</param>
        /// <returns>2進数配列</returns>
        private uint[] ToUInt32Array(string plain_text)
        {
            //文字列を16進数に変換. 実体はbyte配列
            var a = Encoding.ASCII.GetBytes(plain_text);

#if DEBUG
            PrintArray(a);
#endif

            //パディング結果を格納する配列
            uint[] result = { };

            foreach (var n in a)
            {
                //16進数を2進数に変換
                var j = int.Parse(Convert.ToString(n, 2));
                var len = j.ToString().Length;
                var fill_len = 0;

#if DEBUG
                Console.WriteLine("ToBits() : " + j);
#endif

                //2進数を8桁に揃える  0を先頭に追加
                if(len < 8)
                {
                    //2進数が8桁以下であったとき、埋めるべき数は |8 - len| である
                    fill_len = Math.Abs(8 - len);
                    while (fill_len > 0)
                    {
                        fill_len--;
                        SelfAppend(ref result, 0u);
                    }
                }

                SelfConcat(ref result, ToArray((uint)j));
            }

#if DEBUG
            Console.WriteLine("↓ToUInt32Array()");
            PrintArray(result);
#endif

            return result;
        }

        /// <summary>
        /// 配列をいい感じに出力します。
        /// </summary>
        /// <typeparam name="T">アンマネージド型</typeparam>
        /// <param name="source">ソース元である配列</param>
        private void PrintArray<T>(IList<T> source)
        {
            //int[] hoge = { 0, 1, 2, 3, 4 }; -> [ 0, 1, 2, 3, 4 ] (Output)
            Console.WriteLine(string.Format("({0})", source.Count) + "[ " + string.Join(", ", source) + " ]");
        }

        /// <summary>
        /// 配列を右辺へ拡張し、値を格納します。
        /// </summary>
        /// <typeparam name="T">アンマネージド型</typeparam>
        /// <param name="source">ソース元である配列</param>
        /// <param name="num">格納する値</param>
        /// <returns>拡張された配列</returns>
        private T[] Extend<T>(IList<T> source, T num)
        {
            var result = new T[source.Count+1];
            for (int n = 0; n < source.Count; n++)
            {
                result[n] = source[n];
            }
            result[source.Count] = num;
            return result;
        }

        private uint[] ToArray(uint num)
        {
            var s = num.ToString();
            var l = s.Length;
            var r = new uint[l];

            //インデックスは0から始まるので初回の加算で1となるため -1 とする
            int counter = -1;
            foreach (var n in s)
            {
                counter++;
                r[counter] = uint.Parse(n.ToString());
            }

            return r;
        }

        private void SelfAppend<T>(ref T[] source, T num)
        {
            source = source.Append(num).ToArray();
        }

        private void SelfConcat<T>(ref T[] source, T[] destination)
        {
            source = source.Concat(destination).ToArray();
        }

        /// <summary>
        /// Integer から指定されたインデックスにある数値を取り出します。
        /// 12345678 の インデックス 5 の場合 返り値は 5 です。
        /// </summary>
        /// <param name="source">ソース元である数値</param>
        /// <param name="indexN">0から始まるインデックス</param>
        /// <returns>取り出された数値</returns>
        private int StrMid(int source, int indexN)
        {
            var s = source.ToString();
            var result = 0;
            try
            {
                result = int.Parse(s.Substring(indexN, 1));
            }
            catch(Exception ex)
            {
                Console.WriteLine($"StrMid() Exception : {s}[{s.Length}] | {indexN}");
            }
            return result;
        }

        ////////////////////////////////////////////////////////////////////////
        // 論理代数 に関する関数. (Logic Function)
        ////////////////////////////////////////////////////////////////////////

        /// <summary>
        /// 左ローテート
        /// </summary>
        /// <param name="x"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        private uint Rot_L(uint x, byte n)
        {
            return (x << n) | (x >> (32 - n));
        }

        /// <summary>
        /// 右ローテート
        /// </summary>
        /// <param name="x"></param>
        /// <param name="n"></param>
        /// <returns></returns>
        private uint Rot_R(uint x, byte n)
        {
            return (x >> n) | (x << (32 - n));
        }

        /// <summary>
        /// 不明
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <param name="z"></param>
        /// <returns></returns>
        private uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ (~x & z);
        }

        /// <summary>
        /// 変数多数決関数
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        /// <param name="z"></param>
        /// <returns></returns>
        private uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        /// <summary>
        /// 2 13 22
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint Sigma0(uint x)
        {
            return Rot_R(x, 2) ^ Rot_R(x, 13) ^ Rot_R(x, 22);
        }

        /// <summary>
        /// 6 11 25
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint Sigma1(uint x)
        {
            return Rot_R(x, 6) ^ Rot_R(x, 11) ^ Rot_R(x, 25);
        }

        /// <summary>
        /// 7 18 3
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint Sub0(uint x)
        {
            return Rot_R(x, 7) ^ Rot_R(x, 18) ^ (x >> 3);
        }

        /// <summary>
        /// 17 19 10
        /// </summary>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint Sub1(uint x)
        {
            return Rot_R(x, 17) ^ Rot_R(x, 19) ^ (x >> 10);
        }

        /// <summary>
        /// リソースの破棄 未実装
        /// </summary>
        public void Dispose()
        {
            
        }
    }
}
