namespace TruthGate_Web.Models
{
    // Models/PublishJob.cs
    public sealed record PublishJob(
        string Domain,
        string SiteLeaf,
        string TgpLeaf,
        string StagingRoot,   // MFS path containing all uploaded files
        string Note
    );


    public interface IPublishQueue
    {
        ValueTask<string> EnqueueAsync(PublishJob job); // returns jobId
    }

    public interface IPublishRunner
    {
        // for unit tests or manual triggers if you want
    }
}
