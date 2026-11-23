// Isolated regression for bounded Event Log timeout handling. No real events read.
using System;
using System.Diagnostics.Eventing.Reader;

namespace Jarvis.Native.Tests {
    sealed class TimeoutError : EventLogException {
        internal TimeoutError() { HResult=unchecked((int)0x800705B4); }
    }
    sealed class OtherError : EventLogException {
        internal OtherError() { HResult=unchecked((int)0x80070005); }
    }
    static class TimeoutRetry {
        static void Check(bool ok,string name) {
            if(!ok) throw new Exception(name);
        }
        public static int Main() {
            int calls=0;
            int value=Sensor.RetryEventLogTimeout(() => {
                calls++;
                if(calls<3) throw new TimeoutError();
                return 42;
            });
            Check(value==42 && calls==3,"transient timeout retries");

            calls=0;
            try {
                Sensor.RetryEventLogTimeout<int>(() => { calls++; throw new TimeoutError(); });
                throw new Exception("persistent timeout was hidden");
            } catch(TimeoutError) { Check(calls==3,"persistent timeout bound"); }

            calls=0;
            try {
                Sensor.RetryEventLogTimeout<int>(() => { calls++; throw new OtherError(); });
                throw new Exception("other failure was hidden");
            } catch(OtherError) { Check(calls==1,"non-timeout error propagated"); }
            Console.WriteLine("timeout retry checks passed");
            return 0;
        }
    }
}
