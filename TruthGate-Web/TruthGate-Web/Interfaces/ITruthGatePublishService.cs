using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.WebUtilities;

namespace TruthGate_Web.Interfaces
{
    public interface ITruthGatePublishService
    {
        Task<(string JobId, int FileCount)> PublishFromFormAsync(string domain, IFormCollection form, CancellationToken ct);
        Task<(string JobId, int FileCount)> PublishFromMultipartStreamAsync(string domain, MultipartReader reader, CancellationToken ct);
        Task<(string JobId, int FileCount)> PublishFromBrowserFilesAsync(string domain, IEnumerable<(IBrowserFile File, string RelPath)> files, CancellationToken ct);

        Task<(byte[] Bytes, string FileName)> ExportBackupAsync(string domain, string passphrase, CancellationToken ct);
        Task<(string ImportedDomain, string KeyName, string PeerId)> ImportBackupAsync(Stream backupJson, string passphrase, CancellationToken ct);
    }
}
