
using System.Text;
using System.Text.Json;
using backend.DTOs;
using backend.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Mscc.GenerativeAI;
namespace backend.Controllers;

[ApiController]
[Route("ai")]
[Authorize]
public class AiTestController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AiTestController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpGet]
    public async Task<IActionResult> Test()
    {
        var genAi = new GoogleAI(apiKey: _configuration["Gemini:Credentials:ApiKey"]);
        var model = genAi.GenerativeModel(Model.GeminiPro);
        var response = await model.GenerateContent("Hello, world!");
        return Ok(response);
    }
}
