using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuiitaSHA256
{
    //Thank you https://takachan.hatenablog.com/entry/2019/03/05/230952
    public static class StopwatchEx
    {
        public static TimeSpan Context(Action f, int count = 1)
        {
            var sw = new Stopwatch();
            for (int i = 0; i < count; i++)
            {
                sw.Start();
                f();
                sw.Stop();
            }

            return TimeSpan.FromTicks(sw.ElapsedTicks);
        }

        public static TimeSpan Context<TResult>(Func<TResult> f, int count = 1)
        {
            var sw = new Stopwatch();
            sw.Reset();
            for (int i = 0; i < count; i++)
            {
                sw.Start();
                TResult restul = f(); // 読み捨て
                sw.Stop();
            }

            return TimeSpan.FromTicks(sw.ElapsedTicks);
        }
    }
}
