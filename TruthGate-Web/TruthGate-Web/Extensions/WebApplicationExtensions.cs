namespace TruthGate_Web.Extensions
{
    public static class WebApplicationExtensions
    {
        public static WebApplication UseStandardErrorPipeline(this WebApplication app)
        {
            if (app.Environment.IsDevelopment())
            {
                app.UseWebAssemblyDebugging();
            }
            else
            {
                app.UseExceptionHandler("/Error", createScopeForErrors: true);
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseResponseCompression();

            return app;
        }
    }
}
