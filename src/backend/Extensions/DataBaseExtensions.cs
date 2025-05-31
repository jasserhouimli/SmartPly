using backend.Database;
using Microsoft.EntityFrameworkCore;

namespace backend.Extensions;

public static class DataBaseExtensions
{
    public static async Task ApplyMigrationsAsync(this WebApplication app)
    {
        using IServiceScope scope = app.Services.CreateScope();
        await using ApplicationDbContext dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        try
        {
            await dbContext.Database.MigrateAsync();
            app.Logger.LogInformation("Application Database Migrations applied succesfully.");

        }
        catch (Exception e)
        {
            app.Logger.LogError(e, "An error occured while applying Database migrations.");
            throw;
        }
    }
}