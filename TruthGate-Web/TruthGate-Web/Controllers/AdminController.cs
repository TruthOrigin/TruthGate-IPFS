using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;
using TruthGate_Web.Interfaces;

namespace TruthGate_Web.Controllers
{
    [ApiController]
    [Route("api/truthgate/v1/admin")]
    [ServiceFilter(typeof(AdminApiKeyOnlyFilter))]
    public class AdminController : ControllerBase
    {
        private readonly ITruthGatePublishService _svc;

        public AdminController(ITruthGatePublishService svc) => _svc = svc;

        [HttpPost("{domain}/publish")]
        [DisableRequestSizeLimit]
        [RequestFormLimits(ValueCountLimit = int.MaxValue, MultipartBodyLengthLimit = long.MaxValue)]
        public async Task<IActionResult> Publish(string domain, CancellationToken ct)
        {
            var form = await Request.ReadFormAsync(ct);
            try
            {
                var (jobId, count) = await _svc.PublishFromFormAsync(domain, form, ct);
                return Accepted(new { jobId, staged = true, files = count });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpGet("{domain}/backup")]
        public async Task<IActionResult> Backup(string domain, [FromQuery] string passphrase, CancellationToken ct)
        {
            try
            {
                var (bytes, fileName) = await _svc.ExportBackupAsync(domain, passphrase, ct);
                return File(bytes, "application/json", fileName);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("import")]
        public async Task<IActionResult> Import([FromQuery] string passphrase, CancellationToken ct)
        {
            var form = await Request.ReadFormAsync(ct);
            var file = form.Files.FirstOrDefault();
            if (file is null) return BadRequest("Missing backup file.");

            try
            {
                await using var s = file.OpenReadStream();
                var (domain, key, peerId) = await _svc.ImportBackupAsync(s, passphrase, ct);
                return Ok(new { imported = domain, key, peerId });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }

}
