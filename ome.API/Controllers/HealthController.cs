using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ome.Infrastructure.Persistence.Context;

namespace ome.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class HealthController(
    ApplicationDbContext dbContext, 
    ILogger<HealthController> logger,
    IConfiguration configuration,
    HealthCheckService healthCheckService) : ControllerBase 
{
    public ApplicationDbContext DbContext { get; } = dbContext;
    public IConfiguration Configuration { get; } = configuration;

    /// <summary>
    /// Comprehensive health check endpoint for system monitoring
    /// </summary>
    /// <returns>Health status of the system</returns>
    [HttpGet]
    public async Task<IActionResult> Get()
    {
        try
        {
            // Perform comprehensive health check
            var healthReport = await healthCheckService.CheckHealthAsync();

            // Determine overall health status
            var overallStatus = healthReport.Status == HealthStatus.Healthy
                ? (Func<object, IActionResult>)Ok 
                : (Func<object, IActionResult>)(obj => StatusCode(ServiceUnavailable, obj));

            // Prepare detailed health check response
            var response = new
            {
                Status = healthReport.Status.ToString(),
                healthReport.TotalDuration,
                Checks = healthReport.Entries.Select(entry => new
                {
                    Name = entry.Key,
                    Status = entry.Value.Status.ToString(),
                    entry.Value.Description,
                    entry.Value.Duration
                }),
                Timestamp = DateTime.UtcNow
            };

            return overallStatus(response);
        }
        catch (Exception ex)
        {
            // Log unexpected errors
            logger.LogError(ex, "Unexpected error during health check");

            return StatusCode(InternalServerError, new 
            { 
                Status = "Unhealthy", 
                Message = "Critical system error", 
                Timestamp = DateTime.UtcNow 
            });
        }
    }

    // HTTP status code constants for readability
    private const int ServiceUnavailable = 503;
    private const int InternalServerError = 500;
}