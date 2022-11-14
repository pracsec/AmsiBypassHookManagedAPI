using Editor;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace UnitTests {
    [TestClass]
    public class AmsiBypassTests {
        [TestMethod]
        public void AmsiBypassTest() {
            Assert.IsTrue(this.RunMaliciousCommandExpectException(AmsiBypassTests.INVOKE_MIMIKATZ));
            Methods.Patch();
            Assert.IsFalse(this.RunMaliciousCommandExpectException(AmsiBypassTests.INVOKE_MIMIKATZ));
        }

        //private void Foo() {
        //    Type current = typeof(Anchor).Assembly.GetType("Editor.Methods");
        //    MethodInfo method = current.GetMethod("Dummy", BindingFlags.NonPublic | BindingFlags.Static);
        //    foreach (object attribute in method.GetCustomAttributes(false)) {
        //        if (attribute is DllImportAttribute) {
        //            FieldInfo field = typeof(DllImportAttribute).GetField("_val", BindingFlags.NonPublic | BindingFlags.Instance);
        //            field.SetValue(attribute, "kernel32.dll");

        //            field = typeof(DllImportAttribute).GetField("EntryPoint");
        //            field.SetValue(attribute, "WriteProcessMemory");
        //        }
        //    }
        //}

        private bool RunMaliciousCommandExpectException(string script) {
            try {
                PowerShell powershell = PowerShell.Create();
                powershell.AddScript(script);
                PSObject[] results = powershell.Invoke().ToArray<PSObject>();
                return false;
            } catch (ParseException ex) {
                return ex.Message.Contains("malicious content");
            } catch (Exception ex) {
                return false;
            }
        }

        private const string INVOKE_MIMIKATZ = "Invoke-Mimikatz";
        private static readonly string HELLO_EICAR = string.Format("Write-Host '{0}'", AmsiBypassTests.EICAR);
        private const string EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    }
}
