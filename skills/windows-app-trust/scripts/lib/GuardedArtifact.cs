using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Turpial.WindowsTrust {
    // Keep directories non-renamable and the exact target exclusively writable
    // until the staged signed bytes have been copied back through this handle.
    public sealed class GuardedArtifact : IDisposable {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfo {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string name, uint access,
            uint share, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,
            StringBuilder name, uint size, uint flags);
        private readonly List<SafeFileHandle> directories = new List<SafeFileHandle>();
        public FileStream Stream { get; private set; }
        public string FinalPath { get; private set; }
        private GuardedArtifact() {}
        private static FileInfo Inspect(SafeFileHandle handle) {
            FileInfo info;
            if (!GetFileInformationByHandle(handle, out info)) throw new Win32Exception();
            if ((info.Attributes & 0x400) != 0) throw new IOException("Reparse points/junctions/symlinks are not accepted for signing.");
            return info;
        }
        private static string Final(SafeFileHandle handle) {
            var buffer = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity) throw new Win32Exception();
            var value = buffer.ToString();
            if (!value.StartsWith(@"\\?\", StringComparison.Ordinal) || value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Only local filesystem targets are supported for signing.");
            return value.Substring(4);
        }
        private static string LocalPath(string value) {
            string full = Path.GetFullPath(value);
            if (full.Length < 3 || !Char.IsLetter(full[0]) || full[1] != ':' || full[2] != '\\' || full.Substring(2).Contains(":"))
                throw new IOException("Expected a local drive path without an alternate data stream.");
            return full;
        }
        public static GuardedArtifact Open(string artifact, string allowedRoot) {
            return OpenCore(artifact, allowedRoot, true);
        }
        public static GuardedArtifact OpenRead(string artifact) {
            return OpenCore(artifact, Path.GetDirectoryName(LocalPath(artifact)), false);
        }
        private static GuardedArtifact OpenCore(string artifact, string allowedRoot, bool writable) {
            string file = LocalPath(artifact);
            string root = LocalPath(allowedRoot).TrimEnd('\\');
            if (!file.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase))
                throw new IOException("Refusing to sign outside AllowedRoot.");
            var result = new GuardedArtifact();
            SafeFileHandle target = null;
            try {
                string drive = Path.GetPathRoot(file);
                string directory = Path.GetDirectoryName(file);
                var chain = new List<string>();
                chain.Add(drive);
                string cursor = drive;
                foreach (string segment in directory.Substring(drive.Length).Split(new char[] {'\\'}, StringSplitOptions.RemoveEmptyEntries)) {
                    cursor = Path.Combine(cursor, segment); chain.Add(cursor);
                }
                string physicalRoot = null;
                foreach (string entry in chain) {
                    // FILE_READ_ATTRIBUTES; share read/write but never delete;
                    // OPEN_EXISTING + BACKUP_SEMANTICS + OPEN_REPARSE_POINT.
                    var handle = CreateFileW(entry, 0x80, 3, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
                    if (handle.IsInvalid) { int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
                    result.directories.Add(handle);
                    FileInfo info = Inspect(handle);
                    if ((info.Attributes & 0x10) == 0) throw new IOException("Signing ancestor is not a directory.");
                    if (entry.TrimEnd('\\').Equals(root, StringComparison.OrdinalIgnoreCase)) physicalRoot = Final(handle).TrimEnd('\\');
                }
                if (physicalRoot == null) throw new IOException("AllowedRoot was not locked and verified.");
                target = CreateFileW(file, writable ? 0xC0000000u : 0x80000000u, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
                if (target.IsInvalid) throw new Win32Exception();
                FileInfo targetInfo = Inspect(target);
                if ((targetInfo.Attributes & 0x10) != 0 || (writable && targetInfo.Links != 1))
                    throw new IOException("Signing requires a regular file with exactly one hard link.");
                result.FinalPath = Final(target);
                if (!result.FinalPath.StartsWith(physicalRoot + "\\", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Refusing to sign outside the physical AllowedRoot.");
                result.Stream = new FileStream(target, writable ? FileAccess.ReadWrite : FileAccess.Read);
                target = null; // FileStream now owns this handle.
                return result;
            } catch { if (target != null) target.Dispose(); result.Dispose(); throw; }
        }
        public void Dispose() {
            if (Stream != null) { Stream.Dispose(); Stream = null; }
            for (int i = directories.Count - 1; i >= 0; --i) directories[i].Dispose();
            directories.Clear();
        }
    }
}
