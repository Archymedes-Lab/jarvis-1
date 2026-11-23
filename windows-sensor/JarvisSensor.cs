// Windows-native Event Log collector. No PowerShell, WSL, network, or command execution.
// Compile with the installed .NET Framework compiler; references are framework assemblies.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32;

namespace Jarvis.Native {
    public sealed class Sensor : ServiceBase {
        const string Version = "2";
        internal static readonly string[] Channels = {
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational"
        };
        internal static readonly string[] ServiceNames = {
            "JarvisSensorSysmon", "JarvisSensorDefender", "JarvisSensorTasks"
        };
        readonly string root;
        readonly string serviceName;
        readonly string[] selectedChannels;
        readonly ManualResetEvent stop = new ManualResetEvent(false);
        Thread worker;
        const long Capacity = 512L * 1024 * 1024;
        const long SysmonCapacity = 384L * 1024 * 1024;
        const long OtherChannelCapacity = 64L * 1024 * 1024;
        const int BatchEvents = 500;
        // Batches per channel per pass. A backlog drains at up to 25,000
        // records a pass instead of 500 every two seconds, and one busy
        // channel still cannot starve the others for long.
        const int DrainBatches = 50;
        // A busy Event Log service can miss a one-second EvtNext deadline.
        // Keep the retry bounded; a persistent timeout must stay unavailable.
        const int ReadTimeoutSeconds = 2;
        const int ReadTimeoutRetries = 2;
        const int EventLogTimeoutHResult = unchecked((int)0x800705B4);
        // Acknowledged batches stay in the protected spool for a day, so a
        // local copy survives even if the consumer's history is damaged.
        static readonly TimeSpan AckedRetention = TimeSpan.FromHours(24);
        long used;
        static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 16 * 1024 * 1024 };

        [DllImport("kernel32.dll")] static extern ulong GetTickCount64();

        public Sensor(string directory, string name = "JarvisNativeSensor", string channel = null) {
            root = directory; serviceName = name; ServiceName = name;
            selectedChannels = channel == null ? Channels : new [] { channel };
        }
        internal static int ChannelIndex(string service) {
            for(int i=0;i<ServiceNames.Length;i++) if(ServiceNames[i]==service) return i;
            return -1;
        }
        string ChannelDirectory(string channel) { return Path.Combine(root,Hash(channel).Substring(0,16)); }
        long Budget() {
            if(selectedChannels.Length!=1) return Capacity;
            return selectedChannels[0]==Channels[0] ? SysmonCapacity : OtherChannelCapacity;
        }
        string HealthPath() {
            return selectedChannels.Length==1
                ? Path.Combine(ChannelDirectory(selectedChannels[0]),"health.json")
                : Path.Combine(root,"health.json");
        }
        protected override void OnStart(string[] args) {
            worker = new Thread(Run) { IsBackground = true, Name = "jarvis-events" };
            worker.Start();
        }
        protected override void OnStop() { stop.Set(); if(worker != null) worker.Join(15000); }
        static string Hash(string value) {
            return Hex(Encoding.UTF8.GetBytes(value));
        }
        static string Hex(byte[] bytes) {
            using(var sha=SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
        long WriteNew(string path, object value) {
            byte[] bytes = new UTF8Encoding(false).GetBytes(Json.Serialize(value));
            if(bytes.Length > 16 * 1024 * 1024) throw new IOException("Batch too large; bookmark retained");
            string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using(var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) {
                stream.Write(bytes,0,bytes.Length); stream.Flush(true);
            }
            File.Move(temporary,path); // immutable publication; no overwrite of an existing batch
            used += bytes.Length;
            return bytes.Length;
        }
        static Dictionary<string,object> Read(string path) {
            return Json.Deserialize<Dictionary<string,object>>(File.ReadAllText(path));
        }
        void Health(Dictionary<string,object> status) {
            status["schema"]=2; status["version"]=Version; status["time"]=DateTime.UtcNow.ToString("o");
            status["spool_bytes"]=used;
            status["spool_capacity"]=Budget();
            status["service"]=serviceName;
            string path=HealthPath();
            string next=path+"."+Guid.NewGuid().ToString("N")+".new";
            WriteNew(next,status);
            if(File.Exists(path)) File.Replace(next,path,null); else File.Move(next,path);
        }
        string Identity(string file,string key) {
            string path=Path.Combine(root,file);
            if(!File.Exists(path)) {
                try { WriteNew(path,new Dictionary<string,object> { {key,Guid.NewGuid().ToString("D")} }); }
                catch(IOException) { if(!File.Exists(path)) throw; }
            }
            return (string)Read(path)[key];
        }
        // Windows increments this on every boot. With the device identity it
        // separates PID 5412 in one boot from PID 5412 in the next.
        static string BootId() {
            try {
                object v=Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters","BootId",null);
                return v==null ? null : Convert.ToString(v);
            } catch { return null; }
        }
        public void Pass() {
            Directory.CreateDirectory(root);
            bool isolatedMode=File.Exists(Path.Combine(root,"mode.json"));
            if(selectedChannels.Length==1 && !isolatedMode)
                throw new InvalidOperationException("Isolated mode receipt absent; channel publisher paused");
            if(selectedChannels.Length!=1 && isolatedMode)
                throw new InvalidOperationException("Isolated mode active; legacy publisher paused");
            // Separate services have separate capacity budgets. A busy Sysmon
            // stream cannot consume Defender's or Task Scheduler's allowance.
            used=selectedChannels.Length==1
                ? (Directory.Exists(ChannelDirectory(selectedChannels[0]))
                   ? Directory.EnumerateFiles(ChannelDirectory(selectedChannels[0]),"*.json").Sum(p=>new FileInfo(p).Length) : 0)
                : Directory.EnumerateFiles(root,"*",SearchOption.AllDirectories).Sum(p=>new FileInfo(p).Length);
            string sensor=Identity("identity.json","sensor_id");
            // The machine's identity, independent of its renameable hostname.
            string device=Identity("device.json","device_id");
            string boot=BootId();
            var states=new Dictionary<string,object>();
            foreach(string channel in selectedChannels) {
                if(stop.WaitOne(0)) break;
                try {
                    Dictionary<string,object> state=null;
                    for(int i=0;i<DrainBatches && !stop.WaitOne(0);i++) {
                        state=Collect(sensor,device,boot,channel);
                        if(selectedChannels.Length==1) {
                            // Progress receipt during a long backlog drain;
                            // the independent Windows monitor must not mistake
                            // useful work for a hung reader.
                            Health(new Dictionary<string,object> {
                                {"sensor_id",sensor}, {"device_id",device}, {"boot_id",boot},
                                {"host_id",Environment.MachineName},
                                {"channels",new Dictionary<string,object>{{channel,state}}}
                            });
                        }
                        if(Convert.ToInt32(state["events"])<BatchEvents) break;
                    }
                    states[channel]=state;
                }
                catch(Exception e) { states[channel]=new Dictionary<string,object> {
                    {"status","unavailable"}, {"reason",e.GetType().Name+": "+e.Message},
                    {"last_sequence",LatestSequence(channel)} }; }
            }
            string compaction=null;
            try { Compact(); } catch(Exception e) { compaction=e.GetType().Name+": "+e.Message; }
            Health(new Dictionary<string,object> { {"sensor_id",sensor}, {"device_id",device}, {"boot_id",boot},
                {"host_id",Environment.MachineName}, {"channels",states}, {"compaction_error",compaction} });
        }
        Dictionary<string,object> Collect(string sensor,string device,string boot,string channel) {
            if(used >= Budget())
                throw new IOException("Spool capacity reached; collection paused without deleting evidence");
            using(var configuration=new EventLogConfiguration(channel)) {
                if(!configuration.IsEnabled) throw new InvalidOperationException("Event channel is disabled");
            }
            string directory=ChannelDirectory(channel);
            Directory.CreateDirectory(directory);
            string latest=LatestBatch(directory);
            long sequence=0;
            string generation=Guid.NewGuid().ToString("D"), bookmark="";
            if(latest != null) {
                var last=Read(latest);
                if((string)last["sensor_id"] != sensor || (string)last["channel"] != channel) throw new InvalidDataException("Spool identity mismatch");
                sequence=Convert.ToInt64(last["sequence"]); generation=(string)last["generation"]; bookmark=(string)last["bookmark"];
            }
            var events=new List<object>();
            string gap=null;
            // The resume point is the last record ID read. .NET Framework keeps
            // EventBookmark serialization internal, and a record ID can also be
            // compared with what the log still holds, which a bookmark cannot.
            long after=0;
            if(bookmark.StartsWith("record:")) after=Int64.Parse(bookmark.Substring(7));
            var info=EventLogSession.GlobalSession.GetLogInformation(channel,PathType.LogName);
            long oldest=info.OldestRecordNumber ?? 0, count=info.RecordCount ?? 0;
            long newest=count>0 ? oldest+count-1 : 0;
            if(after>0 && newest<after) {
                // Record IDs went backwards: the log was cleared or recreated.
                generation=Guid.NewGuid().ToString("D"); after=0;
                gap="Event log cleared or reset: newest record "+newest+" precedes last read "+bookmark.Substring(7);
            } else if(after>0 && count>0 && oldest>after+1) {
                // The log wrapped before the sensor read these; they are gone for good.
                gap="Records "+(after+1)+"-"+(oldest-1)+" were overwritten or cleared before they were read";
            }
            ReadEvents(channel,after,oldest,count,events,ref bookmark);
            // A full batch is not partial: the drain loop reads the rest at once.
            string status=gap != null ? "partial" : "complete";
            if(bookmark=="" && after>0) bookmark="record:"+after;
            // Empty successful reads still publish bounded cadence health/checkpoints.
            // Throttle heartbeat-only batches to avoid unbounded file churn.
            if(events.Count==0 && gap==null && latest!=null && DateTime.UtcNow-File.GetLastWriteTimeUtc(latest)<TimeSpan.FromMinutes(1))
                return new Dictionary<string,object> { {"status","complete"}, {"last_sequence",sequence}, {"events",0}, {"observed_at",DateTime.UtcNow.ToString("o")} };
            var batch=new Dictionary<string,object> {
                {"schema",2}, {"sensor_id",sensor}, {"device_id",device}, {"boot_id",boot},
                {"host_id",Environment.MachineName}, {"sensor_version",Version},
                {"channel",channel}, {"generation",generation}, {"sequence",sequence+1},
                {"previous_sequence",sequence}, {"created_at",DateTime.UtcNow.ToString("o")},
                {"bookmark",bookmark}, {"status",status}, {"events",events}, {"gap",gap}
            };
            WriteNew(Path.Combine(directory,(sequence+1).ToString("D20")+".json"),batch);
            return new Dictionary<string,object> { {"status",status}, {"last_sequence",sequence+1}, {"events",events.Count}, {"observed_at",DateTime.UtcNow.ToString("o")} };
        }
        long LatestSequence(string channel) {
            string directory=ChannelDirectory(channel);
            if(!Directory.Exists(directory)) return 0;
            string latest=LatestBatch(directory);
            long value;
            return latest!=null && Int64.TryParse(Path.GetFileNameWithoutExtension(latest),out value) ? value : 0;
        }
        static string LatestBatch(string directory) {
            return Directory.EnumerateFiles(directory,"*.json")
                .Where(p=>Path.GetFileNameWithoutExtension(p).Length==20
                    && Path.GetFileNameWithoutExtension(p).All(Char.IsDigit))
                .OrderByDescending(p=>p,StringComparer.Ordinal).FirstOrDefault();
        }
        // Resume by position, not by an EventRecordID XPath predicate. The
        // predicate is evaluated from the oldest record forward, so every batch
        // paid a scan of the whole log: 770 ms to the first event on the
        // 208,860-record Sysmon log (2026-10-12), past the 2 s x 3 read deadline
        // under load -- "The sensor cannot read Sysmon" on 463 passes. A seek by
        // index reached the first event in 26 ms. The index-to-RecordId mapping
        // is approximate, so Position corrects it within fixed bounds and the
        // predicate query stays as the correct-but-slow fallback.
        static void ReadEvents(string channel,long after,long oldest,long count,List<object> events,ref string bookmark) {
            var query=new EventLogQuery(channel,PathType.LogName,"*") { ReverseDirection=false, TolerateQueryErrors=false };
            using(var reader=new EventLogReader(query)) {
                bool converged;
                EventRecord record=Position<EventRecord>(after,oldest,count,
                    index => reader.Seek(SeekOrigin.Begin,index),
                    () => ReadEventWithRetry(reader),
                    RecordIdOf,
                    r => r.Dispose(),
                    out converged);
                if(!converged) { ReadEventsByQuery(channel,after,events,ref bookmark); return; }
                while(record!=null) {
                    using(record) AddEvent(record,events,ref bookmark);
                    if(events.Count>=BatchEvents) break;
                    record=ReadEventWithRetry(reader);
                }
            }
        }
        static long RecordIdOf(EventRecord record) {
            if(!record.RecordId.HasValue) throw new InvalidDataException("Event identity/time missing");
            return record.RecordId.Value;
        }
        // Seek attempts and records skipped per positioning: a fixed bound on
        // work, after which the caller uses the predicate query instead.
        internal const int MaxCorrections = 12;
        internal const int MaxSkip = 50000;
        // Returns the first record whose id is above `after`, or null when the
        // log holds none. A record is returned only when nothing lower and still
        // above `after` can exist: it is after+1, it is the first record in the
        // log, or it directly follows a record at or below `after`. So no record
        // is ever skipped. converged=false (and null) means the bounds ran out;
        // nothing has been emitted and the cursor is unchanged.
        internal static T Position<T>(long after,long oldest,long count,Action<long> seek,Func<T> read,
                                      Func<T,long> id,Action<T> discard,out bool converged) where T:class {
            converged=true;
            if(count<=0) {
                // Reported empty: confirm by reading rather than trusting it.
                seek(0);
                T head=read();
                if(head==null || id(head)>after) return head;
                return SkipForward(head,after,read,id,discard,out converged);
            }
            long index=Math.Min(Math.Max(0,after+1-oldest),count-1);
            // Seek is exact within the result set; what is approximate is the
            // log information (oldest, count) the target index is computed from.
            // lo: largest index seen holding a record at or below the cursor.
            // hi: smallest index seen holding a newer record, or past the end.
            // Each landing moves by the record-id difference it measured, so a
            // near miss costs one more seek; bisection takes over if it bounces.
            long lo=-1, hi=-1, back=Math.Max(1,count/256);
            for(int attempt=0;attempt<=MaxCorrections;attempt++) {
                seek(index);
                T record=read();
                long next;
                if(record==null) {
                    if(index==0) return null;
                    hi=index;
                    next=lo>=0 ? lo+(hi-lo)/2 : Math.Max(0,index-back);
                    back*=2;
                } else {
                    long rid=id(record);
                    if(rid>after) {
                        if(rid==after+1 || index==0) return record;
                        discard(record);
                        hi=index;
                        next=Math.Max(0,index-(rid-after));
                        if(lo>=0 && next<=lo) next=lo+(hi-lo)/2;
                    } else {
                        lo=index;
                        long behind=after-rid;
                        if(behind<=SkipWindow) return SkipForward(record,after,read,id,discard,out converged);
                        discard(record);
                        next=index+behind;
                        if(hi>=0 && next>=hi) next=lo+(hi-lo)/2;
                    }
                }
                if(next==index || (next==lo && lo>=0)) break;
                index=next;
            }
            // Out of seeks: read forward from the best position known to be at or
            // below the cursor, within the skip bound; otherwise report failure.
            if(lo<0) { converged=false; return null; }
            seek(lo);
            T start=read();
            if(start==null || id(start)>after) {
                // The log changed underneath the search; let the caller use the query.
                if(start!=null) discard(start);
                converged=false; return null;
            }
            return SkipForward(start,after,read,id,discard,out converged);
        }
        internal const int SkipWindow = 4096;
        static T SkipForward<T>(T record,long after,Func<T> read,Func<T,long> id,Action<T> discard,out bool converged) where T:class {
            converged=true;
            for(int skipped=0;;skipped++) {
                discard(record);
                if(skipped>=MaxSkip) { converged=false; return null; }
                record=read();
                if(record==null) return null;
                if(id(record)>after) return record;
            }
        }
        static void ReadEventsByQuery(string channel,long after,List<object> events,ref string bookmark) {
            string xpath=after>0 ? "*[System[EventRecordID>"+after+"]]" : "*";
            var query=new EventLogQuery(channel,PathType.LogName,xpath) { ReverseDirection=false, TolerateQueryErrors=false };
            using(var reader=new EventLogReader(query)) {
                while(events.Count<BatchEvents) {
                    using(EventRecord record=ReadEventWithRetry(reader)) {
                        if(record==null) break;
                        AddEvent(record,events,ref bookmark);
                    }
                }
            }
        }
        static void AddEvent(EventRecord record,List<object> events,ref string bookmark) {
            if(!record.RecordId.HasValue || !record.TimeCreated.HasValue) throw new InvalidDataException("Event identity/time missing");
            string xml=record.ToXml();
            if(xml.Length>1024*1024) throw new InvalidDataException("Oversized event; resume point retained");
            events.Add(new Dictionary<string,object> {
                {"record_id",record.RecordId.Value}, {"event_id",record.Id},
                {"time",record.TimeCreated.Value.ToUniversalTime().ToString("o")},
                // Preserve observation time separately from the
                // provider's event time so backlog and latency
                // remain measurable without rewriting history.
                {"read_time",DateTime.UtcNow.ToString("o")},
                // Milliseconds since boot when read: orders records within a
                // boot even if the wall clock is changed underneath.
                {"mono_ms",(long)GetTickCount64()}, {"xml",xml}
            });
            bookmark="record:"+record.RecordId.Value;
        }
        static EventRecord ReadEventWithRetry(EventLogReader reader) {
            return RetryEventLogTimeout(() => reader.ReadEvent(TimeSpan.FromSeconds(ReadTimeoutSeconds)));
        }
        internal static T RetryEventLogTimeout<T>(Func<T> read) {
            for(int attempt=0;;attempt++) {
                try { return read(); }
                catch(EventLogException e) {
                    // ERROR_TIMEOUT is not EOF. Keep the cursor and channel
                    // unavailable if every bounded attempt fails.
                    if(e.HResult!=EventLogTimeoutHResult || attempt>=ReadTimeoutRetries) throw;
                }
            }
        }
        // Reclaims only what the consumer has acknowledged by sequence and exact
        // digest, never the newest batch (the resume point), and only after the
        // retention period or under space pressure. Without acknowledgements the
        // spool fills and collection stops: known blindness, not lost evidence.
        void Compact() {
            string acks=Path.Combine(root,"acks");
            if(!Directory.Exists(acks)) return;
            bool pressure=used >= Budget()/2;
            foreach(string directory in Directory.EnumerateDirectories(root)) {
                string name=Path.GetFileName(directory);
                if(name.Length!=16) continue;
                if(selectedChannels.Length==1 && directory!=ChannelDirectory(selectedChannels[0])) continue;
                string ackPath=Path.Combine(acks,name+".json");
                if(!File.Exists(ackPath)) continue;
                var ack=Read(ackPath);
                long through=Convert.ToInt64(ack["through_sequence"]);
                string acked=Path.Combine(directory,through.ToString("D20")+".json");
                if(!File.Exists(acked)) continue;
                var head=Read(acked);
                if((string)head["channel"] != (string)ack["channel"] || (string)head["sensor_id"] != (string)ack["sensor_id"]) continue;
                if(Hex(File.ReadAllBytes(acked)) != (string)ack["digest"]) continue;
                foreach(string file in Directory.EnumerateFiles(directory,"*.json").ToList()) {
                    long seq;
                    if(!Int64.TryParse(Path.GetFileNameWithoutExtension(file),out seq) || seq>=through) continue;
                    var info=new FileInfo(file);
                    if(!pressure && DateTime.UtcNow-info.LastWriteTimeUtc<AckedRetention) continue;
                    long length=info.Length;
                    File.Delete(file);
                    used-=length;
                }
            }
        }
        void Run() {
            // Exclusive process lock protects immutable sequence allocation.
            Directory.CreateDirectory(root);
            string lockPath=selectedChannels.Length==1
                ? Path.Combine(ChannelDirectory(selectedChannels[0]),"sensor.lock")
                : Path.Combine(root,"sensor.lock");
            if(selectedChannels.Length==1) Directory.CreateDirectory(ChannelDirectory(selectedChannels[0]));
            using(var gate=new FileStream(lockPath,FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) {
                do {
                    try { Pass(); }
                    catch(Exception e) { try { Health(new Dictionary<string,object>{{"status","unavailable"},{"reason",e.GetType().Name+": "+e.Message}}); } catch {} }
                } while(!stop.WaitOne(2000));
            }
        }
        public static int Main(string[] args) {
            string directory=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Jarvis","Sensor");
            if(args.Length==2 && args[0]=="--once") {
                // Explicit path used only for local testing, never supplied to the service.
                using(var sensor=new Sensor(Path.GetFullPath(args[1]))) {
                    Directory.CreateDirectory(sensor.root);
                    using(var gate=new FileStream(Path.Combine(sensor.root,"sensor.lock"),FileMode.OpenOrCreate,FileAccess.ReadWrite,FileShare.None)) sensor.Pass();
                }
                return 0;
            }
            if(args.Length==2 && args[0]=="--service") {
                int index=ChannelIndex(args[1]);
                if(index<0) return 2;
                ServiceBase.Run(new Sensor(directory,args[1],Channels[index]));
                return 0;
            }
            if(args.Length!=0) return 2;
            ServiceBase.Run(new Sensor(directory));
            return 0;
        }
    }
}
