// Isolated regression for positional resume (Sensor.Position). No real events read.
// The fake log maps a seek index to a record with a configurable error, the way
// the real Sysmon channel landed 43 records short of after+1-oldest.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Jarvis.Native.Tests {
    sealed class Rec { internal long Id; }
    sealed class FakeLog {
        readonly long[] ids; readonly Func<long,long> land; int at; bool readFails;
        internal int Seeks, Reads, Discards;
        internal FakeLog(long[] ids, Func<long,long> land, bool readFails=false) {
            this.ids=ids; this.land=land; this.readFails=readFails;
        }
        internal void Seek(long index) { Seeks++; at=(int)Math.Max(0,Math.Min(ids.Length,land(index))); }
        internal Rec Read() {
            Reads++;
            if(readFails) throw new TimeoutException("read deadline");
            return at<ids.Length ? new Rec { Id=ids[at++] } : null;
        }
        internal Rec Position(long after, long oldest, long count, out bool converged) {
            return Sensor.Position<Rec>(after, oldest, count, Seek, Read, r => r.Id, r => Discards++, out converged);
        }
    }
    static class PositionResume {
        static int failures;
        static void Check(bool ok, string name) {
            if(!ok) { failures++; Console.WriteLine("FAIL: "+name); }
        }
        static long[] Range(long first, int n) { return Enumerable.Range(0,n).Select(i => first+i).ToArray(); }
        // The invariant: the lowest record id above the cursor, or null when none exists.
        static long? Expected(long[] ids, long after) {
            foreach(long id in ids) if(id>after) return id;
            return null;
        }
        static void Case(string name, long[] ids, long after, Func<long,long> land) {
            Case(name, ids, after, land, ids.Length>0 ? ids[0] : 0, ids.Length);
        }
        // reportedOldest/reportedCount model stale log information: the real
        // Sysmon channel landed 43 records short of after+1-oldest.
        static void Case(string name, long[] ids, long after, Func<long,long> land, long reportedOldest, long reportedCount) {
            var log=new FakeLog(ids, land);
            bool converged;
            Rec r=log.Position(after, reportedOldest, reportedCount, out converged);
            long? want=Expected(ids, after);
            Check(converged, name+": converged");
            Check((r==null ? (long?)null : r.Id)==want, name+": first record "+(r==null?"null":r.Id.ToString())+" want "+(want==null?"null":want.ToString()));
            Check(log.Seeks<=Sensor.MaxCorrections+1, name+": seek bound ("+log.Seeks+")");
        }
        public static int Main() {
            long[] log=Range(3602709, 208860);
            long newest=log[log.Length-1];
            long after=newest-5000;
            Case("exact mapping", log, after, i => i);
            Case("lands 43 short (measured)", log, after, i => i-43);
            Case("lands 43 past", log, after, i => i+43);
            Case("reported oldest 43 low", log, after, i => i, log[0]-43, log.Length);
            Case("reported oldest 43 high", log, after, i => i, log[0]+43, log.Length);
            Case("reported oldest far high, count stale", log, after, i => i, log[0]+60000, log.Length+60000);
            Case("lands far past", log, after, i => i+40000);
            Case("cursor before oldest (wrapped)", log, log[0]-900000, i => i);
            Case("no cursor yet", log, 0, i => i);
            Case("cursor at newest", log, newest, i => i);
            Case("cursor beyond newest", log, newest+10, i => i);
            Case("empty log", new long[0], 1234, i => i);

            // Record ids with holes: the lowest id above the cursor may be far above it.
            var holes=new List<long>();
            for(long id=1000; holes.Count<5000; id+=(holes.Count%97==0 ? 50 : 1)) holes.Add(id);
            long[] gapped=holes.ToArray();
            Case("id holes, cursor inside a hole", gapped, gapped[2000]+1, i => i);
            Case("id holes, lands short", gapped, gapped[3000]-3, i => i-200);
            Case("id holes, lands past", gapped, gapped[3000]-3, i => i+200);

            // The log holds fewer records than it reported: reads at the estimate are empty.
            Case("log shorter than reported", Range(500, 1000), 1200, i => i, 500-5000, 6000);
            Case("log shorter than reported, cursor at end", Range(500, 1000), 1499, i => i, 500-5000, 6000);

            // Every landing overshoots: the bound runs out, nothing is returned, the
            // caller falls back to the query. No record is emitted from a guess.
            var stubborn=new FakeLog(log, i => log.Length-1);
            bool c;
            Rec none=stubborn.Position(after, log[0], log.Length, out c);
            Check(!c && none==null, "overshoot bound returns not-converged");
            Check(stubborn.Seeks==Sensor.MaxCorrections+1, "overshoot bound stops at MaxCorrections");

            // A long skip forward is bounded too.
            var far=new FakeLog(log, i => 0);
            Rec skipped=far.Position(log[0]+Sensor.MaxSkip+10, log[0], log.Length, out c);
            Check(!c && skipped==null, "skip bound returns not-converged");
            Check(far.Discards<=Sensor.MaxSkip+Sensor.MaxCorrections+2, "skip bound limits discarded records");

            // A read failure propagates: nothing is returned and the caller keeps its cursor.
            var broken=new FakeLog(log, i => i, readFails:true);
            try { broken.Position(after, log[0], log.Length, out c); Check(false, "read failure was hidden"); }
            catch(TimeoutException) { Check(true, "read failure propagated"); }

            // Randomized: holes in record ids, stale log information, any cursor.
            // Whenever Position converges its answer must be exact; it must
            // converge on almost every realistic case.
            var rng=new Random(20261012);
            int trials=3000, fellBack=0;
            for(int t=0;t<trials;t++) {
                var ids=new List<long>();
                long id=rng.Next(1,1000000);
                int n=rng.Next(0,20000);
                for(int i=0;i<n;i++) { ids.Add(id); id+=rng.Next(100)==0 ? rng.Next(2,300) : 1; }
                long[] arr=ids.ToArray();
                long first=arr.Length>0 ? arr[0] : 0, last=arr.Length>0 ? arr[arr.Length-1] : 0;
                long cursor=first-500+(long)(rng.NextDouble()*(last-first+1000));
                long rOldest=first+rng.Next(-2000,2000);
                long rCount=Math.Max(0,arr.Length+rng.Next(-2000,2000));
                var fake=new FakeLog(arr, i => i);
                bool ok;
                Rec got=fake.Position(cursor, rOldest, rCount, out ok);
                long? want=Expected(arr, cursor);
                if(!ok) { fellBack++; Check(got==null, "random "+t+": not-converged must return null"); continue; }
                Check((got==null ? (long?)null : got.Id)==want, "random "+t+": exact first record");
                Check(fake.Seeks<=Sensor.MaxCorrections+2, "random "+t+": seek bound");
            }
            Check(fellBack*100<trials, "random: fell back on "+fellBack+" of "+trials);

            if(failures>0) { Console.WriteLine(failures+" position checks failed"); return 1; }
            Console.WriteLine("position resume checks passed");
            return 0;
        }
    }
}
