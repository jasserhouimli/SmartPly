using backend.DTOs;
using backend.Exceptions;
using backend.Results;
using backend.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("auth")]
[AllowAnonymous]
public sealed class AuthController(IAuthService authService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterUserDto dto)
    {
        var result = await authService.RegisterAsync(dto);
        return result.IsSuccess ? Ok(result) : BadRequest(result);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginUserDto dto)
    {
        var result = await authService.LoginAsync(dto);
        return result.IsSuccess ? Ok(result) : Unauthorized(result);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh(RefreshTokenDto dto)
    {
        var result = await authService.RefreshTokenAsync(dto);
        return result.IsSuccess ? Ok(result) : Unauthorized(result);
    }

    [HttpGet("google/authorize")]
    public IActionResult GoogleAuthorize()
    {
        return Ok(new { AuthorizationUrl = authService.GetGoogleAuthorizationUrl() });
    }

    [HttpGet("google/callback")]
    public async Task<IActionResult> GoogleCallback(string code, string state, string? error)
    {
        try
        {
            var redirectUrl = await authService.HandleGoogleCallbackAsync(code, state, error);
            return Redirect(redirectUrl);
        }
        catch (AuthException ex)
        {
            return BadRequest(new AuthFailure(ex.Message));
        }
    }
}
