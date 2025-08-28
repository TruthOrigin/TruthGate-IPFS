using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using System.Text;
using TruthGate_Web.Endpoints;
using TruthGate_Web.Models;
using TruthGate_Web.Services;
using TruthGate_Web.Utils;
using TruthGate_Web.Interfaces;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using TruthGate_Web.Middleware;

namespace TruthGate_Web.Controllers
{

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class DisableFormValueModelBindingAttribute : Attribute, IResourceFilter
    {
        public void OnResourceExecuting(ResourceExecutingContext context)
        {
            var factories = context.ValueProviderFactories;
            factories.RemoveType<FormValueProviderFactory>();
            factories.RemoveType<FormFileValueProviderFactory>();
            factories.RemoveType<JQueryFormValueProviderFactory>();
        }

        public void OnResourceExecuted(ResourceExecutedContext context) { }
    }

    [AdminProtected]
    [ApiController]
    [Route("api/truthgate/v1/admin")]
    [ServiceFilter(typeof(AdminApiKeyOnlyFilter))]
    [DisableFormValueModelBinding] // <- critical
    [DisableRequestSizeLimit]
    [RequestFormLimits(ValueCountLimit = int.MaxValue, MultipartBodyLengthLimit = long.MaxValue)]
    public class AdminController : ControllerBase
    {
        private readonly ITruthGatePublishService _svc;

        public AdminController(ITruthGatePublishService svc) => _svc = svc;

        [HttpPost("{domain}/publish")]
        [DisableRequestSizeLimit]
        [RequestFormLimits(ValueCountLimit = int.MaxValue, MultipartBodyLengthLimit = long.MaxValue)]
        public async Task<IActionResult> Publish(string domain, CancellationToken ct)
        {
            // Expect multipart/form-data
            if (!MediaTypeHeaderValue.TryParse(Request.ContentType, out var mediaType))
                return BadRequest("Missing or invalid Content-Type.");

            var boundary = HeaderUtilities.RemoveQuotes(mediaType.Boundary).Value;
            if (string.IsNullOrWhiteSpace(boundary))
                return BadRequest("Missing multipart boundary.");

            var reader = new MultipartReader(boundary, Request.Body)
            {
                BodyLengthLimit = long.MaxValue,   // section size (default ~128MB)
                HeadersCountLimit = 512,             // many clients repeat headers
                HeadersLengthLimit = 256 * 1024,      // long filenames / relpaths
                                                      // BufferSize       = 64 * 1024,       // optional: larger line buffer
            };


            try
            {
                var (jobId, count) = await _svc.PublishFromMultipartStreamAsync(
                    domain: domain,
                    reader: reader,
                    ct: ct);

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
